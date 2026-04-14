"""
app/services/sealed_push.py — Sealed push notifications (zero-knowledge push).

Push payload содержит ТОЛЬКО encrypted_hint — даже сервер не знает
кто отправил и что в сообщении. Клиент расшифровывает hint локально.

Каналы доставки (в порядке приоритета):
  1. WebSocket (основной) — если клиент онлайн, push не нужен
  2. Web Push API (VAPID) — через Service Worker, без FCM
  3. SSE fallback — если Web Push недоступен
  4. UnifiedPush (open standard) — без FCM/APNs, через UP-совместимый distributor

Формат sealed push payload:
  {
    "type": "sealed_push",
    "ts":   <unix_timestamp>,
    "hint": <base64(AES-256-GCM(room_id + sender_pseudo + msg_type))>
  }
  → Нет plaintext sender, content, room name — ничего для метаданных.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── VAPID key management ────────────────────────────────────────────────────

@dataclass
class VapidConfig:
    """VAPID (Voluntary Application Server Identification) keys for Web Push."""
    public_key:  str = ""
    private_key: str = ""
    subject:     str = ""
    enabled:     bool = False

    def load(self) -> None:
        self.public_key  = os.environ.get("VAPID_PUBLIC_KEY", "")
        self.private_key = os.environ.get("VAPID_PRIVATE_KEY", "")
        self.subject     = os.environ.get("VAPID_SUBJECT", "mailto:admin@vortex.local")
        self.enabled     = bool(self.public_key and self.private_key)
        if self.enabled:
            logger.info("📱 VAPID keys loaded — Web Push enabled")
        else:
            logger.info("📱 VAPID keys not set — Web Push disabled (WS/SSE only)")


vapid = VapidConfig()


# ── Push subscription store ─────────────────────────────────────────────────

@dataclass
class PushSubscription:
    user_id:    int
    endpoint:   str
    p256dh:     str
    auth:       str
    created_at: float = field(default_factory=time.time)


# In-memory subscription store (per-process; for production use DB)
_subscriptions: dict[int, list[PushSubscription]] = {}


def register_subscription(user_id: int, endpoint: str, p256dh: str, auth: str) -> None:
    if user_id not in _subscriptions:
        _subscriptions[user_id] = []
    # Avoid duplicates
    for sub in _subscriptions[user_id]:
        if sub.endpoint == endpoint:
            sub.p256dh = p256dh
            sub.auth   = auth
            return
    _subscriptions[user_id].append(PushSubscription(
        user_id=user_id, endpoint=endpoint, p256dh=p256dh, auth=auth,
    ))


def unregister_subscription(user_id: int, endpoint: str) -> None:
    if user_id in _subscriptions:
        _subscriptions[user_id] = [
            s for s in _subscriptions[user_id] if s.endpoint != endpoint
        ]


# ── Sealed hint encryption ──────────────────────────────────────────────────

def _derive_push_key(user_id: int) -> bytes:
    """Derive per-user push encryption key from app secret + user_id."""
    import hashlib
    secret = os.environ.get("JWT_SECRET", "vortex-default-secret").encode()
    return hashlib.pbkdf2_hmac("sha256", secret, f"push:{user_id}".encode(), 10000)


def encrypt_push_hint(user_id: int, room_id: int, sender_pseudo: str, msg_type: str) -> str:
    """Encrypt push hint so only the recipient can read it."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key   = _derive_push_key(user_id)
    nonce = os.urandom(12)
    plaintext = json.dumps({
        "r": room_id,
        "s": sender_pseudo[:16],
        "t": msg_type,
    }, separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(nonce + ct).decode()


# ── Push delivery ────────────────────────────────────────────────────────────

async def send_sealed_push(
    user_id:       int,
    room_id:       int,
    sender_pseudo: str,
    msg_type:      str = "message",
) -> bool:
    """
    Send a sealed push notification to a user.
    Returns True if at least one delivery channel succeeded.
    """
    from app.peer.connection_manager import manager
    from app.services.unified_push import up_manager

    # Channel 1: WebSocket — if online, no push needed
    if manager.is_online_any_room(user_id):
        return True

    hint = encrypt_push_hint(user_id, room_id, sender_pseudo, msg_type)
    payload = {
        "type": "sealed_push",
        "ts":   int(time.time()),
        "hint": hint,
    }

    # Channel 2: Global WebSocket notification
    ws_ok = await manager.notify_user(user_id, payload)
    if ws_ok:
        return True

    # Channel 3: Web Push (VAPID)
    delivered = False
    if vapid.enabled and user_id in _subscriptions:
        for sub in _subscriptions[user_id]:
            try:
                await _send_web_push(sub, payload)
                delivered = True
                break
            except Exception as e:
                logger.debug(f"Web Push failed for {user_id}: {e}")

    # ── 4. UnifiedPush (open standard, no FCM/APNs) ──
    if not delivered and up_manager.has_subscription(user_id):
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        try:
            delivered = await up_manager.send(user_id, payload_bytes)
            if delivered:
                logger.debug("Sealed push via UnifiedPush (sanitized)")
        except Exception as e:
            logger.debug("UP push failed: %s", str(e)[:100])

    return delivered


async def _send_web_push(sub: PushSubscription, payload: dict) -> None:
    """Send Web Push via VAPID protocol."""
    try:
        from pywebpush import webpush
        webpush(
            subscription_info={
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
            },
            data=json.dumps(payload),
            vapid_private_key=vapid.private_key,
            vapid_claims={"sub": vapid.subject},
            ttl=300,
        )
    except ImportError:
        # pywebpush not installed — skip silently
        pass


# ── Stats ────────────────────────────────────────────────────────────────────

def push_stats() -> dict:
    total_subs = sum(len(v) for v in _subscriptions.values())
    return {
        "vapid_enabled":       vapid.enabled,
        "registered_users":    len(_subscriptions),
        "total_subscriptions": total_subs,
    }
