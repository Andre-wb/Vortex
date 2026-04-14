"""
app/chats/sfu.py — E2E-capable SFU (Selective Forwarding Unit).

Опакный SFU: пересылает RTP-пакеты между участниками без
декодирования/кодирования медиа.  Это сохраняет E2E-шифрование
медиа-фреймов (AES-256-GCM через Insertable Streams).

Архитектура:
  - aiortc обеспечивает ICE / DTLS для каждого участника
  - RTP-пакеты перехватываются на уровне DTLS-транспорта
    (monkey-patch ``_handle_rtp_data``)
  - Пересылаются другим участникам через их DTLS-транспорт
    (``_send_rtp``) с ремаппингом SSRC
  - Кодек **не задействован** → E2E payload проходит без изменений

Endpoints:
  POST /api/sfu/{call_id}/join   — SDP offer → answer
  POST /api/sfu/{call_id}/leave  — disconnect
  GET  /api/sfu/available        — check SFU
  WS   /ws/sfu/{call_id}         — renegotiation + ICE
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security.auth_jwt import get_current_user, get_user_ws

logger = logging.getLogger("vortex.sfu")
router = APIRouter(tags=["sfu"])

# ── Configuration ────────────────────────────────────────────────────────────

SFU_THRESHOLD = int(os.getenv("SFU_THRESHOLD", "6"))
SFU_MAX_PARTICIPANTS = int(os.getenv("SFU_MAX_PARTICIPANTS", "200"))

# ── Simulcast layers ────────────────────────────────────────────────────────
# Client sends 3 simultaneous video streams (high/medium/low)
# SFU selects which layer to forward to each subscriber based on viewport

SIMULCAST_LAYERS = {
    "high":   {"maxBitrate": 2_500_000, "maxFramerate": 30, "scaleDown": 1},
    "medium": {"maxBitrate":   600_000, "maxFramerate": 20, "scaleDown": 2},
    "low":    {"maxBitrate":   150_000, "maxFramerate": 10, "scaleDown": 4},
}

# Default subscription quality per viewer position
DEFAULT_VIEWPORT_QUALITY = "medium"

# Dominant speaker detection interval (seconds)
SPEAKER_DETECT_INTERVAL = 0.3

# ── Conditional aiortc import ────────────────────────────────────────────────

try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, RTCIceCandidate  # type: ignore
    _SFU_AVAILABLE = True
except ImportError:
    _SFU_AVAILABLE = False
    logger.info("[SFU] aiortc not installed — SFU unavailable, mesh-only fallback")


def is_sfu_available() -> bool:
    return _SFU_AVAILABLE


# ── In-memory state ──────────────────────────────────────────────────────────

_sfu_rooms: dict[str, SFURoom] = {}


# ── Models ───────────────────────────────────────────────────────────────────

class SFUOfferRequest(BaseModel):
    sdp: str


class SFUAnswerResponse(BaseModel):
    sdp: str
    type: str = "answer"
    participants: list[dict] = []


# ── SDP utilities ────────────────────────────────────────────────────────────

def _parse_pt_kinds(sdp: str) -> dict[int, str]:
    """Extract ``payload_type → 'audio'|'video'`` mapping from SDP."""
    result: dict[int, str] = {}
    current_kind: str | None = None
    for line in sdp.split("\r\n"):
        if not line and "\n" in sdp:
            continue
        if line.startswith("m=audio"):
            current_kind = "audio"
            for tok in line.split()[3:]:
                try:
                    result[int(tok)] = "audio"
                except ValueError:
                    pass
        elif line.startswith("m=video"):
            current_kind = "video"
            for tok in line.split()[3:]:
                try:
                    result[int(tok)] = "video"
                except ValueError:
                    pass
        elif line.startswith("a=rtpmap:") and current_kind:
            try:
                pt = int(line.split(":")[1].split()[0])
                result[pt] = current_kind
            except (ValueError, IndexError):
                pass
    return result


# ── SFU Participant ──────────────────────────────────────────────────────────

@dataclass
class SFUParticipant:
    user_id: int
    username: str
    display_name: str = ""
    avatar_emoji: str = ""
    avatar_url: str = ""
    pc: object | None = None                                # RTCPeerConnection
    ws: WebSocket | None = None                             # renegotiation WS
    ready_sources: set = field(default_factory=set)         # UIDs whose media can be forwarded here
    pending_sources: list = field(default_factory=list)     # UIDs awaiting renegotiation
    # Simulcast: which layer to forward per source user
    # {source_uid: "high" | "medium" | "low" | "none"}
    subscriptions: dict = field(default_factory=dict)
    # Simulcast: SSRC → layer mapping from client's SDP (populated on join)
    simulcast_ssrcs: dict = field(default_factory=dict)     # {(kind, layer): ssrc}
    # Audio level tracking for dominant speaker detection
    audio_level: float = 0.0
    audio_level_ts: float = 0.0


# ── SFU Room ─────────────────────────────────────────────────────────────────

class SFURoom:
    """
    Opaque RTP forwarding room for a single group call.

    Each participant has one ``RTCPeerConnection`` to the SFU.
    RTP packets are intercepted at the DTLS transport level (before the
    codec) and forwarded to all other participants with SSRC remapping.
    E2E-encrypted payloads pass through the SFU unchanged.
    """

    def __init__(self, call_id: str, room_id: int):
        self.call_id = call_id
        self.room_id = room_id
        self.participants: dict[int, SFUParticipant] = {}
        # (target_uid, source_uid, kind) → SSRC to use when forwarding
        self._send_ssrc_table: dict[tuple, int] = {}
        # payload_type → 'audio' | 'video'  (built from first negotiated SDP)
        self._pt_to_kind: dict[int, str] = {}
        self._lock = asyncio.Lock()
        # Simulcast: source_uid → {ssrc → layer} mapping
        self._simulcast_map: dict[int, dict[int, str]] = {}
        # Dominant speaker state
        self._dominant_speaker_id: int | None = None
        self._speaker_task: asyncio.Task | None = None
        # Stats
        self._total_rtp_forwarded: int = 0
        self._total_rtp_dropped: int = 0
        logger.info("[SFU] Room created: call=%s room=%s (simulcast + viewport + E2E)", call_id, room_id)

    @property
    def participant_count(self) -> int:
        return len(self.participants)

    # ── Join ──────────────────────────────────────────────────────────────

    async def join(self, user: User, offer_sdp: str) -> tuple[str, list[dict]]:
        """
        Process participant SDP offer, return ``(answer_sdp, participants_list)``.

        1. Create ``RTCPeerConnection`` (ICE + DTLS)
        2. Process SDP offer → answer (accept client's media)
        3. Patch DTLS transport for opaque RTP forwarding
        4. Add *sendonly* transceivers for other participants' forwarded media
        5. Trigger renegotiation on existing participants to add this user's media
        """
        if not _SFU_AVAILABLE:
            raise RuntimeError("aiortc not installed")

        async with self._lock:
            pc = RTCPeerConnection()
            participant = SFUParticipant(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name or user.username,
                avatar_emoji=user.avatar_emoji or "",
                avatar_url=user.avatar_url or "",
                pc=pc,
            )

            @pc.on("track")
            async def on_track(track):
                logger.info("[SFU] Track %s from user %s", track.kind, user.id)

            @pc.on("connectionstatechange")
            async def on_state():
                state = pc.connectionState
                logger.debug("[SFU] user %s state: %s", user.id, state)
                if state in ("failed", "closed"):
                    asyncio.ensure_future(self.leave(user.id))

            # ── SDP offer → answer ───────────────────────────────────────
            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=offer_sdp, type="offer")
            )
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)

            # Build PT → kind map from negotiated SDP (once)
            if not self._pt_to_kind:
                self._pt_to_kind = _parse_pt_kinds(pc.localDescription.sdp)
                self._pt_to_kind.update(_parse_pt_kinds(offer_sdp))

            # ── Patch DTLS transport for opaque forwarding ───────────────
            self._patch_transport(user.id, pc)

            self.participants[user.id] = participant

            # ── Sendonly transceivers: this PC receives other participants ─
            for other_uid in list(self.participants):
                if other_uid == user.id:
                    continue
                self._add_send_transceivers(pc, target_uid=user.id, source_uid=other_uid)
                participant.pending_sources.append(other_uid)

            # ── Sendonly transceivers: existing PCs receive this new user ──
            for other_uid, other in list(self.participants.items()):
                if other_uid == user.id:
                    continue
                self._add_send_transceivers(other.pc, target_uid=other_uid, source_uid=user.id)
                other.pending_sources.append(user.id)
                asyncio.ensure_future(self._try_renegotiate(other))

            plist = [
                {
                    "user_id": p.user_id,
                    "username": p.username,
                    "display_name": p.display_name,
                    "avatar_emoji": p.avatar_emoji,
                    "avatar_url": p.avatar_url,
                }
                for p in self.participants.values()
                if p.user_id != user.id
            ]

            logger.info("[SFU] user %s joined (opaque). total=%s", user.id, self.participant_count)

            # Notify existing participants about the new joiner
            for uid, p in self.participants.items():
                if uid != user.id and p.ws:
                    try:
                        await p.ws.send_json({
                            "type": "sfu_participant_joined",
                            "user_id": user.id,
                            "username": user.username,
                            "display_name": user.display_name or user.username,
                            "avatar_emoji": user.avatar_emoji or "",
                            "avatar_url": user.avatar_url or "",
                        })
                    except Exception:
                        pass

            return pc.localDescription.sdp, plist

    # ── Sendonly transceivers (for SDP negotiation) ──────────────────────

    def _add_send_transceivers(self, pc, target_uid: int, source_uid: int) -> None:
        """Add sendonly audio + video transceivers for forwarding *source*'s media to *target*."""
        for kind in ("audio", "video"):
            t = pc.addTransceiver(kind, direction="sendonly")
            self._send_ssrc_table[(target_uid, source_uid, kind)] = t.sender._ssrc
            logger.debug(
                "[SFU] sendonly %s: target=%s source=%s ssrc=%s",
                kind, target_uid, source_uid, t.sender._ssrc,
            )

    # ── Transport patching (opaque RTP interception) ─────────────────────

    def _patch_transport(self, uid: int, pc) -> None:
        """Monkey-patch DTLS transport's ``_handle_rtp_data`` for opaque forwarding."""
        transport = self._get_transport(pc)
        if not transport or getattr(transport, "_vortex_patched", False):
            return

        original_handle = transport._handle_rtp_data
        room = self

        async def _forwarding_handle(data: bytes, arrival_time_ms: int) -> None:
            # Forward RTP opaquely (preserves E2E encrypted payloads)
            await room._forward_rtp(uid, data)
            # Let aiortc process for RTCP stats (decode may fail — harmless)
            try:
                await original_handle(data, arrival_time_ms)
            except Exception:
                pass

        transport._handle_rtp_data = _forwarding_handle
        transport._vortex_patched = True  # type: ignore[attr-defined]
        logger.debug("[SFU] Patched DTLS transport for user %s", uid)

    # ── RTP forwarding ───────────────────────────────────────────────────

    async def _forward_rtp(self, from_uid: int, rtp_data: bytes) -> None:
        """Forward an RTP packet with simulcast layer selection and viewport filtering."""
        if len(rtp_data) < 12:
            return

        pt = rtp_data[1] & 0x7F
        kind = self._pt_to_kind.get(pt)
        if not kind:
            return

        # Extract source SSRC for simulcast layer detection
        src_ssrc = struct.unpack_from(">I", rtp_data, 8)[0]

        # Detect simulcast layer of this packet
        source_layer = "high"  # default
        layer_map = self._simulcast_map.get(from_uid, {})
        if layer_map and src_ssrc in layer_map:
            source_layer = layer_map[src_ssrc]

        # Audio level extraction for dominant speaker (RTP header extension)
        if kind == "audio":
            self._update_audio_level(from_uid, rtp_data)

        for uid, peer in self.participants.items():
            if uid == from_uid or not peer.pc:
                continue
            if from_uid not in peer.ready_sources:
                continue

            # Viewport selection: check what quality this viewer wants
            if kind == "video":
                wanted = peer.subscriptions.get(from_uid, DEFAULT_VIEWPORT_QUALITY)
                if wanted == "none":
                    self._total_rtp_dropped += 1
                    continue  # Viewer doesn't want this source's video
                # Only forward if this packet's layer matches or is the best available
                if not self._layer_matches(source_layer, wanted):
                    self._total_rtp_dropped += 1
                    continue

            ssrc = self._send_ssrc_table.get((uid, from_uid, kind))
            if not ssrc:
                continue

            # Rewrite SSRC in raw RTP header (bytes 8-11)
            rewritten = bytearray(rtp_data)
            struct.pack_into(">I", rewritten, 8, ssrc)

            try:
                target_transport = self._get_transport(peer.pc)
                if target_transport:
                    await target_transport._send_rtp(bytes(rewritten))
                    self._total_rtp_forwarded += 1
            except Exception:
                pass

    @staticmethod
    def _layer_matches(source_layer: str, wanted_layer: str) -> bool:
        """Check if source simulcast layer should be forwarded for wanted quality."""
        layers = {"low": 0, "medium": 1, "high": 2}
        return layers.get(source_layer, 2) == layers.get(wanted_layer, 1)

    def _update_audio_level(self, uid: int, rtp_data: bytes) -> None:
        """Extract audio level from RTP for dominant speaker detection."""
        import time
        p = self.participants.get(uid)
        if not p:
            return
        # Simple heuristic: use payload size as rough volume proxy
        # Real implementation would parse RFC 6464 header extension
        payload_size = len(rtp_data) - 12
        level = min(payload_size / 200.0, 1.0)  # normalize
        # Exponential moving average
        now = time.monotonic()
        alpha = 0.3
        p.audio_level = alpha * level + (1 - alpha) * p.audio_level
        p.audio_level_ts = now

    # ── Renegotiation ────────────────────────────────────────────────────

    async def _try_renegotiate(self, participant: SFUParticipant) -> None:
        """Create and push a renegotiation offer (new sendonly tracks)."""
        if not participant.ws or not participant.pc:
            return
        try:
            offer = await participant.pc.createOffer()
            await participant.pc.setLocalDescription(offer)
            await participant.ws.send_json({
                "type": "sfu_offer",
                "sdp": participant.pc.localDescription.sdp,
            })
            logger.debug("[SFU] renegotiation offer → user %s", participant.user_id)
        except Exception as e:
            logger.warning("[SFU] renegotiation failed for %s: %s", participant.user_id, e)

    # ── Handle client messages ───────────────────────────────────────────

    async def handle_answer(self, user_id: int, sdp: str) -> None:
        """Process renegotiation answer — mark forwarding targets as ready."""
        p = self.participants.get(user_id)
        if not p or not p.pc:
            return
        try:
            await p.pc.setRemoteDescription(
                RTCSessionDescription(sdp=sdp, type="answer")
            )
            p.ready_sources.update(p.pending_sources)
            p.pending_sources.clear()
            logger.debug("[SFU] answer OK for %s, ready_sources=%s", user_id, p.ready_sources)
        except Exception as e:
            logger.warning("[SFU] answer error for %s: %s", user_id, e)

    async def handle_ice(self, user_id: int, candidate_data: dict) -> None:
        p = self.participants.get(user_id)
        if not p or not p.pc:
            return
        try:
            await p.pc.addIceCandidate(RTCIceCandidate(
                sdpMid=candidate_data.get("sdpMid", ""),
                sdpMLineIndex=candidate_data.get("sdpMLineIndex", 0),
                candidate=candidate_data.get("candidate", ""),
            ))
        except Exception as e:
            logger.debug("[SFU] ICE error for %s: %s", user_id, e)

    # ── Leave / cleanup ──────────────────────────────────────────────────

    async def leave(self, user_id: int) -> None:
        async with self._lock:
            p = self.participants.pop(user_id, None)
            if not p:
                return
            if p.pc:
                await p.pc.close()

            # Clean SSRC table entries involving this user
            stale_keys = [k for k in self._send_ssrc_table if k[0] == user_id or k[1] == user_id]
            for k in stale_keys:
                del self._send_ssrc_table[k]

            for uid, other in self.participants.items():
                other.ready_sources.discard(user_id)

            logger.info("[SFU] user %s left. remaining=%s", user_id, self.participant_count)

            for uid, other in self.participants.items():
                if other.ws:
                    try:
                        await other.ws.send_json({
                            "type": "sfu_participant_left",
                            "user_id": user_id,
                            "username": p.username,
                        })
                    except Exception:
                        pass

            if not self.participants:
                _sfu_rooms.pop(self.call_id, None)
                logger.info("[SFU] Room %s closed (empty)", self.call_id)

    # ── Viewport subscription ───────────────────────────────────────────

    async def handle_subscribe(self, user_id: int, subscriptions: dict) -> None:
        """
        Update viewport subscriptions for a participant.

        subscriptions: { str(source_user_id): "high" | "medium" | "low" | "none" }

        This determines which simulcast layer to forward for each source.
        Unspecified sources default to DEFAULT_VIEWPORT_QUALITY.
        """
        p = self.participants.get(user_id)
        if not p:
            return
        # Convert string keys to int
        p.subscriptions = {int(k): v for k, v in subscriptions.items() if v in ("high", "medium", "low", "none")}
        logger.debug("[SFU] user %s subscriptions: %s", user_id, p.subscriptions)

    async def handle_simulcast_info(self, user_id: int, layers: dict) -> None:
        """
        Client reports SSRC → layer mapping for its simulcast streams.

        layers: { "high": ssrc_int, "medium": ssrc_int, "low": ssrc_int }
        """
        mapping = {}
        for layer_name, ssrc in layers.items():
            if layer_name in ("high", "medium", "low") and isinstance(ssrc, int):
                mapping[ssrc] = layer_name
        self._simulcast_map[user_id] = mapping
        logger.debug("[SFU] user %s simulcast map: %s", user_id, mapping)

    # ── Dominant speaker detection ───────────────────────────────────────

    async def _start_speaker_detection(self) -> None:
        """Start the dominant speaker detection background loop."""
        if self._speaker_task and not self._speaker_task.done():
            return
        self._speaker_task = asyncio.create_task(self._speaker_detection_loop())

    async def _speaker_detection_loop(self) -> None:
        """Periodically detect the loudest speaker and broadcast."""
        import time
        while self.participants:
            await asyncio.sleep(SPEAKER_DETECT_INTERVAL)
            try:
                now = time.monotonic()
                best_uid = None
                best_level = 0.05  # threshold — ignore quiet

                for uid, p in self.participants.items():
                    # Only consider recent audio (last 2 seconds)
                    if now - p.audio_level_ts > 2.0:
                        continue
                    if p.audio_level > best_level:
                        best_level = p.audio_level
                        best_uid = uid

                if best_uid != self._dominant_speaker_id:
                    self._dominant_speaker_id = best_uid
                    # Broadcast to all participants
                    for uid, p in self.participants.items():
                        if p.ws:
                            try:
                                await p.ws.send_json({
                                    "type": "sfu_dominant_speaker",
                                    "user_id": best_uid,
                                    "level": round(best_level, 3),
                                })
                            except Exception:
                                pass
            except Exception as e:
                logger.debug("[SFU] Speaker detection error: %s", e)

    # ── Stats ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return SFU room statistics."""
        return {
            "call_id": self.call_id,
            "room_id": self.room_id,
            "participant_count": self.participant_count,
            "dominant_speaker": self._dominant_speaker_id,
            "rtp_forwarded": self._total_rtp_forwarded,
            "rtp_dropped": self._total_rtp_dropped,
            "simulcast_sources": len(self._simulcast_map),
            "subscriptions": {
                uid: dict(p.subscriptions)
                for uid, p in self.participants.items()
                if p.subscriptions
            },
        }

    def set_ws(self, user_id: int, ws: WebSocket) -> None:
        p = self.participants.get(user_id)
        if p:
            p.ws = ws
            if p.pending_sources:
                asyncio.ensure_future(self._try_renegotiate(p))
            # Start speaker detection on first WS
            asyncio.ensure_future(self._start_speaker_detection())

    async def close(self) -> None:
        async with self._lock:
            for p in self.participants.values():
                if p.pc:
                    await p.pc.close()
            self.participants.clear()
            _sfu_rooms.pop(self.call_id, None)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _get_transport(pc):
        """Return the shared DTLS transport for a PeerConnection (BUNDLE)."""
        try:
            for t in pc.getTransceivers():
                transport = getattr(t.receiver, "transport", None)
                if transport:
                    return transport
                transport = getattr(t.sender, "transport", None)
                if transport:
                    return transport
        except Exception:
            pass
        return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_or_create_sfu_room(call_id: str, room_id: int) -> SFURoom:
    if call_id not in _sfu_rooms:
        _sfu_rooms[call_id] = SFURoom(call_id, room_id)
    return _sfu_rooms[call_id]


# ── REST Endpoints ───────────────────────────────────────────────────────────

@router.get("/api/sfu/available")
async def sfu_available():
    return {
        "available": _SFU_AVAILABLE,
        "threshold": SFU_THRESHOLD,
        "max_participants": SFU_MAX_PARTICIPANTS,
        "simulcast": True,
        "viewport_selection": True,
        "dominant_speaker": True,
        "layers": list(SIMULCAST_LAYERS.keys()),
    }


@router.get("/api/sfu/{call_id}/stats")
async def sfu_stats(call_id: str, user: User = Depends(get_current_user)):
    """Get SFU room statistics (simulcast, viewport, speaker, bandwidth)."""
    room = _sfu_rooms.get(call_id)
    if not room:
        raise HTTPException(404, "SFU room not found")
    return room.get_stats()


@router.post("/api/sfu/{call_id}/join")
async def sfu_join(
    call_id: str,
    req: SFUOfferRequest,
    user: User = Depends(get_current_user),
):
    if not _SFU_AVAILABLE:
        raise HTTPException(501, detail="SFU unavailable (aiortc not installed)")

    from app.chats.group_calls import _active_group_calls
    gc = _active_group_calls.get(call_id)
    if not gc:
        raise HTTPException(404, detail="Call not found")

    room = get_or_create_sfu_room(call_id, gc.room_id)
    if room.participant_count >= SFU_MAX_PARTICIPANTS:
        raise HTTPException(409, detail="Call is full")

    try:
        answer_sdp, participants = await room.join(user, req.sdp)
    except Exception as e:
        logger.error("[SFU] join failed for %s: %s", user.id, e)
        raise HTTPException(500, detail="SFU join failed")

    return SFUAnswerResponse(sdp=answer_sdp, participants=participants)


@router.post("/api/sfu/{call_id}/leave")
async def sfu_leave(call_id: str, user: User = Depends(get_current_user)):
    room = _sfu_rooms.get(call_id)
    if room:
        await room.leave(user.id)
    return {"ok": True}


# ── WebSocket — renegotiation + ICE ──────────────────────────────────────────

@router.websocket("/ws/sfu/{call_id}")
async def ws_sfu(
    websocket: WebSocket,
    call_id: str,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Bidirectional signaling for SFU renegotiation and ICE.

    Client → SFU:
      ``{ type: "sfu_answer", sdp: "..." }``    — renegotiation answer
      ``{ type: "sfu_ice", candidate: {...} }``  — ICE candidate

    SFU → Client:
      ``{ type: "sfu_offer", sdp: "..." }``                — renegotiation
      ``{ type: "sfu_participant_joined", user_id, ... }``  — new participant
      ``{ type: "sfu_participant_left",   user_id, ... }``  — participant left
    """
    raw_token = websocket.cookies.get("access_token") or token
    if not raw_token:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    try:
        user = await get_user_ws(raw_token, db)
    except HTTPException:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    await websocket.accept()

    room = _sfu_rooms.get(call_id)
    if not room:
        await websocket.close(code=4404)
        return

    room.set_ws(user.id, websocket)
    logger.debug("[SFU-WS] user %s connected, call %s", user.id, call_id)

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "sfu_answer":
                await room.handle_answer(user.id, data.get("sdp", ""))
            elif msg_type == "sfu_ice":
                await room.handle_ice(user.id, data.get("candidate", {}))
            elif msg_type == "sfu_subscribe":
                # Viewport selection: client tells SFU what quality per user
                # { type: "sfu_subscribe", subscriptions: { "user_5": "high", "user_8": "medium", ... } }
                await room.handle_subscribe(user.id, data.get("subscriptions", {}))
            elif msg_type == "sfu_simulcast_info":
                # Client reports its simulcast SSRC mapping
                # { type: "sfu_simulcast_info", layers: { "high": ssrc1, "medium": ssrc2, "low": ssrc3 } }
                await room.handle_simulcast_info(user.id, data.get("layers", {}))
            else:
                logger.debug("[SFU-WS] unknown type from %s: %s", user.id, msg_type)

    except WebSocketDisconnect:
        logger.debug("[SFU-WS] user %s disconnected", user.id)
    except Exception as e:
        logger.warning("[SFU-WS] error for %s: %s", user.id, e)
    finally:
        p = room.participants.get(user.id) if room else None
        if p:
            p.ws = None
