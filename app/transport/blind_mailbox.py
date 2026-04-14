"""
app/transport/blind_mailbox.py — Blind Mailbox Protocol (BMP)

Metadata-private transport layer. Server does not know who talks to whom.
Clients derive rotating mailbox IDs from shared secrets and use cover traffic
to make real operations indistinguishable from fake ones.

Endpoints:
  POST /api/bmp/post/{mailbox_id}     — deposit encrypted message
  POST /api/bmp/batch                  — fetch multiple mailboxes in one request
  GET  /api/bmp/stats                  — server-side stats (admin)
  DELETE /api/bmp/gc                   — manual garbage collection (admin)
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

# ── Rust backend (50x faster) with Python fallback ──────────────────────────
try:
    import vortex_chat as _vc
    _RUST_BMP = True
    logger.info("[BMP] Rust backend loaded (vortex_chat %s)", _vc.VERSION)
except ImportError:
    _RUST_BMP = False
    logger.warning("[BMP] Rust backend not available — Python fallback active")

router = APIRouter(prefix="/api/bmp", tags=["blind-mailbox"])

# ── Configuration ────────────────────────────────────────────────────────────

BMP_MAX_MSG_SIZE = 64 * 1024          # 64 KB max per message
BMP_MAX_MSGS_PER_BOX = 200            # max messages per mailbox
BMP_TTL_SECONDS = 7200                # 2 hours — messages expire
BMP_GC_INTERVAL = 300                 # garbage collection every 5 min
BMP_MAX_BATCH = 100                   # max mailboxes per batch request
BMP_RATE_LIMIT_PER_MIN = 600          # max operations per user per minute


# ── In-memory Mailbox Store ──────────────────────────────────────────────────

@dataclass
class MailboxMessage:
    ciphertext: str           # hex-encoded encrypted payload
    timestamp: float          # time.time() when deposited
    size: int                 # payload size in bytes


class BlindMailboxStore:
    """
    In-memory store for blind mailboxes.

    Design:
    - No user IDs stored — only mailbox_id → [messages]
    - Server cannot link mailbox_id to any user
    - Messages expire after TTL
    - Periodic garbage collection removes expired messages
    """

    def __init__(self):
        self._boxes: dict[str, list[MailboxMessage]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._total_deposited: int = 0
        self._total_fetched: int = 0
        self._total_expired: int = 0
        self._gc_task: Optional[asyncio.Task] = None

    async def deposit(self, mailbox_id: str, ciphertext: str) -> bool:
        """Deposit encrypted message into a mailbox. Returns True on success."""
        if _RUST_BMP:
            return _vc.bmp_deposit(mailbox_id, ciphertext)

        # Python fallback
        if len(ciphertext) > BMP_MAX_MSG_SIZE * 2:
            return False

        async with self._lock:
            box = self._boxes[mailbox_id]
            if len(box) >= BMP_MAX_MSGS_PER_BOX:
                box.pop(0)

            box.append(MailboxMessage(
                ciphertext=ciphertext,
                timestamp=time.time(),
                size=len(ciphertext) // 2,
            ))
            self._total_deposited += 1
        return True

    async def fetch(self, mailbox_id: str, since_ts: float = 0) -> list[dict]:
        """Fetch messages from a mailbox since timestamp."""
        now = time.time()
        async with self._lock:
            box = self._boxes.get(mailbox_id, [])
            result = []
            for msg in box:
                if msg.timestamp > since_ts and (now - msg.timestamp) < BMP_TTL_SECONDS:
                    result.append({
                        "ct": msg.ciphertext,
                        "ts": msg.timestamp,
                    })
            self._total_fetched += 1
        return result

    async def fetch_batch(self, mailbox_ids: list[str], since_ts: float = 0) -> dict[str, list[dict]]:
        """Fetch multiple mailboxes in one call. Returns {id: [messages]}."""
        if _RUST_BMP:
            raw = _vc.bmp_fetch_batch(mailbox_ids, since_ts)
            # Convert Rust format [(ct, ts)] → [{"ct": ct, "ts": ts}]
            return {k: [{"ct": ct, "ts": ts} for ct, ts in v] for k, v in raw.items()}

        # Python fallback
        now = time.time()
        result = {}
        async with self._lock:
            for mb_id in mailbox_ids[:BMP_MAX_BATCH]:
                box = self._boxes.get(mb_id, [])
                msgs = []
                for msg in box:
                    if msg.timestamp > since_ts and (now - msg.timestamp) < BMP_TTL_SECONDS:
                        msgs.append({
                            "ct": msg.ciphertext,
                            "ts": msg.timestamp,
                        })
                if msgs:
                    # Bucket timestamps to 5-minute windows to prevent timing leaks
                    for m in msgs:
                        m["ts"] = int(m["ts"] / 300) * 300
                    result[mb_id] = msgs
                # NOTE: empty mailboxes return nothing — server can't distinguish
                # real empty from non-existent (both return no data)
            self._total_fetched += 1
        return result

    async def gc(self) -> int:
        """Remove expired messages. Returns count removed."""
        if _RUST_BMP:
            return _vc.bmp_gc()

        now = time.time()
        removed = 0
        async with self._lock:
            for mb_id in list(self._boxes.keys()):
                box = self._boxes[mb_id]
                before = len(box)
                self._boxes[mb_id] = [
                    m for m in box if (now - m.timestamp) < BMP_TTL_SECONDS
                ]
                removed += before - len(self._boxes[mb_id])
                if not self._boxes[mb_id]:
                    del self._boxes[mb_id]
            self._total_expired += removed
        if removed:
            logger.info("[BMP] GC: removed %d expired messages, %d active boxes",
                        removed, len(self._boxes))
        return removed

    def stats(self) -> dict:
        if _RUST_BMP:
            return _vc.bmp_stats()
        return {
            "active_mailboxes": len(self._boxes),
            "total_messages": sum(len(b) for b in self._boxes.values()),
            "total_deposited": self._total_deposited,
            "total_fetched": self._total_fetched,
            "total_expired": self._total_expired,
            "ttl_seconds": BMP_TTL_SECONDS,
            "max_batch": BMP_MAX_BATCH,
        }

    async def start_gc_loop(self):
        """Start background GC loop."""
        if self._gc_task and not self._gc_task.done():
            return
        self._gc_task = asyncio.create_task(self._gc_loop())

    async def _gc_loop(self):
        while True:
            await asyncio.sleep(BMP_GC_INTERVAL)
            try:
                await self.gc()
            except Exception as e:
                logger.debug("[BMP] GC error: %s", e)


# ── Global store instance ────────────────────────────────────────────────────

store = BlindMailboxStore()


# ── Rate limiting (per-IP, not per-user — we don't track users) ──────────────

_rate_counters: dict[str, list[float]] = defaultdict(list)


def _check_rate(ip: str) -> bool:
    """Returns True if under rate limit."""
    if _RUST_BMP:
        return _vc.bmp_check_rate(ip)
    now = time.time()
    window = _rate_counters[ip]
    _rate_counters[ip] = [t for t in window if now - t < 60]
    if len(_rate_counters[ip]) >= BMP_RATE_LIMIT_PER_MIN:
        return False
    _rate_counters[ip].append(now)
    return True


def _get_ip(request: Request) -> str:
    from app.security.ip_privacy import raw_ip_for_ratelimit
    return raw_ip_for_ratelimit(request)


# ── Request/Response models ──────────────────────────────────────────────────

class DepositRequest(BaseModel):
    ct: str = Field(..., min_length=24, max_length=BMP_MAX_MSG_SIZE * 2,
                    description="Hex-encoded E2E encrypted message")


class BatchRequest(BaseModel):
    ids: list[str] = Field(..., min_length=1, max_length=BMP_MAX_BATCH,
                           description="List of mailbox IDs to fetch")
    since: float = Field(0, description="Fetch messages newer than this timestamp")


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/post/{mailbox_id}")
async def bmp_deposit(
    mailbox_id: str,
    body: DepositRequest,
    request: Request,
):
    """
    Deposit an encrypted message into a blind mailbox.

    No authentication required — anyone can write to any mailbox.
    Server does not know who is writing or for whom.
    Rate limited by IP.
    """
    if len(mailbox_id) < 16 or len(mailbox_id) > 64:
        raise HTTPException(400, "Invalid mailbox ID length")

    if not _check_rate(_get_ip(request)):
        raise HTTPException(429, "Rate limit exceeded")

    ok = await store.deposit(mailbox_id, body.ct)
    if not ok:
        raise HTTPException(413, "Message too large")

    return {"ok": True}


@router.post("/batch")
async def bmp_batch(
    body: BatchRequest,
    request: Request,
):
    """
    Fetch messages from multiple mailboxes in one request.

    Client sends a mix of real + cover mailbox IDs.
    Server cannot distinguish which are real.
    Returns only mailboxes that have messages (empty = omitted).
    """
    if not _check_rate(_get_ip(request)):
        raise HTTPException(429, "Rate limit exceeded")

    result = await store.fetch_batch(body.ids, body.since)
    # Pad response to prevent size-based fingerprinting of message volume
    import secrets as _s
    return {"mailboxes": result, "_p": _s.token_urlsafe(128 + _s.randbelow(384))}


@router.get("/stats")
async def bmp_stats(u: User = Depends(get_current_user)):
    """BMP store statistics (authenticated, for admin dashboard)."""
    return store.stats()


@router.delete("/gc")
async def bmp_manual_gc(u: User = Depends(get_current_user)):
    """Trigger manual garbage collection."""
    removed = await store.gc()
    return {"removed": removed, **store.stats()}


# ── Startup helper ───────────────────────────────────────────────────────────

async def start_bmp():
    """Call from app lifespan to start BMP GC loop."""
    if _RUST_BMP:
        _vc.bmp_start_gc()
        logger.info("[BMP] Rust backend started (TTL=%ds, max_batch=%d)", BMP_TTL_SECONDS, BMP_MAX_BATCH)
    else:
        await store.start_gc_loop()
        logger.info("[BMP] Python fallback started (TTL=%ds, max_batch=%d)", BMP_TTL_SECONDS, BMP_MAX_BATCH)


# ═══════════════════════════════════════════════════════════════════════════════
# UNIFIED BMP TRANSPORT — Room Secret Store + Envelope Deposit
# ═══════════════════════════════════════════════════════════════════════════════

import hashlib
import hmac
import json
import math
import secrets as _secrets

BMP_FAST_RATE_LIMIT = 3000  # higher rate for fast-poll during calls
BMP_ROTATION_PERIOD = 3600  # 1 hour — must match client ROTATION_PERIOD


class BMPRoomSecretStore:
    """
    Stores room_id → BMP secret (HKDF-derived from room key on client side).
    The server does NOT know the room key — only the BMP-derived secret
    which is sufficient to compute mailbox IDs for deposit.

    Thread-safe via asyncio lock.
    """

    def __init__(self):
        self._secrets: dict[int, str] = {}  # room_id → hex secret
        self._lock = asyncio.Lock()

    async def set_secret(self, room_id: int, secret_hex: str):
        if _RUST_BMP:
            _vc.bmp_set_room_secret(room_id, secret_hex)
            return
        async with self._lock:
            self._secrets[room_id] = secret_hex

    async def get_secret(self, room_id: int) -> str | None:
        if _RUST_BMP:
            return _vc.bmp_get_room_secret(room_id)
        async with self._lock:
            return self._secrets.get(room_id)

    async def remove_secret(self, room_id: int):
        async with self._lock:
            self._secrets.pop(room_id, None)


room_secrets = BMPRoomSecretStore()


BMP_ROTATION_JITTER = 600  # ±10 min per-pair jitter
BMP_CLOCK_SKEW_EPOCHS = 1  # accept ±1 epoch


def _pair_jitter(bmp_secret_hex: str) -> int:
    """Compute per-pair rotation jitter (0..599 seconds) from secret."""
    secret_bytes = bytes.fromhex(bmp_secret_hex)
    jitter_sig = hmac.new(secret_bytes, b'jitter', hashlib.sha256).digest()
    return ((jitter_sig[0] << 8) | jitter_sig[1]) % BMP_ROTATION_JITTER


def compute_mailbox_id(bmp_secret_hex: str, timestamp: float | None = None) -> str:
    """
    Compute mailbox ID with per-pair rotation jitter.
    Mirrors client-side deriveMailboxId().
    """
    ts = timestamp or time.time()
    jitter = _pair_jitter(bmp_secret_hex)
    adjusted_ts = ts - jitter
    epoch = int(adjusted_ts / BMP_ROTATION_PERIOD)
    epoch_bytes = epoch.to_bytes(8, 'big')
    secret_bytes = bytes.fromhex(bmp_secret_hex)
    sig = hmac.new(secret_bytes, epoch_bytes, hashlib.sha256).digest()
    return sig[:16].hex()


def compute_mailbox_ids(bmp_secret_hex: str, timestamp: float | None = None) -> list[str]:
    """
    Compute mailbox IDs for current + adjacent epochs (clock skew tolerance).
    Returns list of 3 IDs: [prev_epoch, current, next_epoch].
    """
    ts = timestamp or time.time()
    jitter = _pair_jitter(bmp_secret_hex)
    adjusted_ts = ts - jitter
    epoch = int(adjusted_ts / BMP_ROTATION_PERIOD)
    secret_bytes = bytes.fromhex(bmp_secret_hex)
    ids = []
    for e in range(epoch - BMP_CLOCK_SKEW_EPOCHS, epoch + BMP_CLOCK_SKEW_EPOCHS + 1):
        epoch_bytes = max(0, e).to_bytes(8, 'big')
        sig = hmac.new(secret_bytes, epoch_bytes, hashlib.sha256).digest()
        ids.append(sig[:16].hex())
    return ids


async def deposit_envelope(room_id: int, envelope_hex: str) -> bool:
    """
    Deposit an encrypted envelope into the BMP mailbox for a room.

    Looks up the room's BMP secret, computes the current mailbox ID,
    and deposits the envelope.

    Args:
        room_id: Room ID
        envelope_hex: Hex-encoded encrypted envelope (from client pack or server)

    Returns:
        True if deposited successfully, False if no secret or deposit failed
    """
    if _RUST_BMP:
        return _vc.bmp_deposit_envelope(room_id, envelope_hex)

    # Python fallback
    secret = await room_secrets.get_secret(room_id)
    if not secret:
        return False

    mailbox_ids = compute_mailbox_ids(secret)
    ok = False
    for mb_id in mailbox_ids:
        if await store.deposit(mb_id, envelope_hex):
            ok = True
            _emit_wake_signal(mb_id)

    return ok


def _emit_wake_signal(mailbox_id: str):
    """
    Emit an anonymous wake signal for the push proxy.
    Category = SHA256(mailbox_id) mod 256.
    The push proxy knows categories → push tokens.
    The mailbox server knows mailbox_id → category.
    Neither knows the full picture.
    """
    category = hashlib.sha256(mailbox_id.encode()).digest()[0]  # 0-255
    # TODO Phase 6: Send wake signal to push proxy service
    # For now, just log
    logger.debug("[BMP] Wake signal category=%d for mailbox %s", category, mailbox_id[:8])


# ── BMP Secret Registration Endpoint ──────────────────────────────────────────

class BMPSecretRequest(BaseModel):
    secret: str = Field(..., min_length=64, max_length=64,
                        description="Hex-encoded 32-byte HKDF-derived BMP secret")


@router.post("/room-secret/{room_id}")
async def register_room_secret(
    room_id: int,
    body: BMPSecretRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Register a BMP secret for a room.

    Client derives this from the room key via HKDF(info="bmp-mailbox").
    The server uses it to compute mailbox IDs for depositing envelopes.
    The server CANNOT derive the room key from this secret (one-way HKDF).
    """
    # Verify user is member of the room
    from app.models_rooms import RoomMember
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Not a member of this room")

    await room_secrets.set_secret(room_id, body.secret)
    logger.debug("[BMP] Room secret registered (sanitized)")
    return {"ok": True}


# ── Fast Batch Endpoint (for WebRTC signaling, Phase 4) ──────────────────────

@router.post("/fast-batch")
async def bmp_fast_batch(
    body: BatchRequest,
    request: Request,
):
    """
    Fast batch fetch — same as /batch but with higher rate limit.
    Used during call setup for 500ms polling.
    """
    ip = _get_ip(request)
    now = time.time()
    # Use separate fast rate counter
    window = _fast_rate_counters[ip]
    _fast_rate_counters[ip] = [t for t in window if now - t < 60]
    if len(_fast_rate_counters[ip]) >= BMP_FAST_RATE_LIMIT:
        raise HTTPException(429, "Rate limit exceeded")
    _fast_rate_counters[ip].append(now)

    result = await store.fetch_batch(body.ids, body.since)
    return {"mailboxes": result, "_p": _secrets.token_urlsafe(128 + _secrets.randbelow(384))}


_fast_rate_counters: dict[str, list[float]] = defaultdict(list)
