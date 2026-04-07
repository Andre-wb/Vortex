from __future__ import annotations

import json as _json
import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Room, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user, get_user_ws

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stream", tags=["stream"])
ws_router = APIRouter(tags=["stream"])


class StreamRole(str, Enum):
    HOST = "host"
    CO_HOST = "co_host"
    SPEAKER = "speaker"
    VIEWER = "viewer"


class StreamParticipant:
    __slots__ = (
        "user_id", "username", "display_name", "avatar_emoji", "avatar_url",
        "role", "can_speak", "can_video", "can_screen_share",
        "is_muted", "is_video_on", "is_screen_sharing",
        "hand_raised", "joined_at",
    )

    def __init__(self, user: User, role: StreamRole):
        self.user_id = user.id
        self.username = user.username
        self.display_name = user.display_name or user.username
        self.avatar_emoji = user.avatar_emoji or "\U0001f464"
        self.avatar_url = user.avatar_url
        self.role = role
        # Permissions
        self.can_speak = role in (StreamRole.HOST, StreamRole.CO_HOST, StreamRole.SPEAKER)
        self.can_video = role in (StreamRole.HOST, StreamRole.CO_HOST, StreamRole.SPEAKER)
        self.can_screen_share = role in (StreamRole.HOST, StreamRole.CO_HOST)
        # State
        self.is_muted = role == StreamRole.VIEWER
        self.is_video_on = False
        self.is_screen_sharing = False
        self.hand_raised = False
        self.joined_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "avatar_emoji": self.avatar_emoji,
            "avatar_url": self.avatar_url,
            "role": self.role.value,
            "can_speak": self.can_speak,
            "can_video": self.can_video,
            "can_screen_share": self.can_screen_share,
            "is_muted": self.is_muted,
            "is_video_on": self.is_video_on,
            "is_screen_sharing": self.is_screen_sharing,
            "hand_raised": self.hand_raised,
            "joined_at": self.joined_at,
        }


class StreamState:
    """In-memory state of an active stream."""

    def __init__(self, room_id: int, host: User, title: str, description: str,
                 allow_reactions: bool, allow_donations: bool, donation_card: str,
                 donation_message: str, auto_accept_speakers: bool):
        self.room_id = room_id
        self.host_id = host.id
        self.title = title
        self.description = description
        self.allow_reactions = allow_reactions
        self.allow_donations = allow_donations
        self.donation_card = donation_card
        self.donation_message = donation_message
        self.auto_accept_speakers = auto_accept_speakers
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.participants: dict[int, StreamParticipant] = {}
        self.hand_queue: list[int] = []  # user_ids in order of raising hand
        self.reaction_counts: dict[str, int] = {}  # emoji -> count
        self.donations: list[dict] = []  # [{user_id, username, amount, message, timestamp}]
        self.viewer_peak = 0

        # Add host as first participant
        host_p = StreamParticipant(host, StreamRole.HOST)
        host_p.can_screen_share = True
        self.participants[host.id] = host_p

    def viewer_count(self) -> int:
        return len(self.participants)

    def to_dict(self) -> dict:
        return {
            "room_id": self.room_id,
            "host_id": self.host_id,
            "title": self.title,
            "description": self.description,
            "allow_reactions": self.allow_reactions,
            "allow_donations": self.allow_donations,
            "donation_card": self.donation_card or "",
            "donation_message": self.donation_message or "",
            "auto_accept_speakers": self.auto_accept_speakers,
            "started_at": self.started_at,
            "viewer_count": self.viewer_count(),
            "viewer_peak": self.viewer_peak,
            "participants": [p.to_dict() for p in self.participants.values()],
            "hand_queue": self.hand_queue,
            "reaction_counts": self.reaction_counts,
        }


_active_streams: dict[int, StreamState] = {}  # room_id -> StreamState
_stream_ws: dict[int, dict[int, WebSocket]] = {}  # room_id -> {user_id -> WS}


class StartStreamRequest(BaseModel):
    title: str = Field("", max_length=200)
    description: str = Field("", max_length=1000)
    allow_reactions: bool = True
    allow_donations: bool = False
    donation_card: str = Field("", max_length=200)
    donation_message: str = Field("", max_length=500)
    auto_accept_speakers: bool = False


class GrantPermissionRequest(BaseModel):
    user_id: int
    can_speak: Optional[bool] = None
    can_video: Optional[bool] = None
    can_screen_share: Optional[bool] = None
    role: Optional[str] = Field(None, pattern="^(co_host|speaker|viewer)$")


class SendDonationRequest(BaseModel):
    amount: str = Field(..., min_length=1, max_length=50)
    message: str = Field("", max_length=300)
    currency: str = Field("RUB", max_length=10)


class UpdateStreamRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    allow_reactions: Optional[bool] = None
    allow_donations: Optional[bool] = None
    donation_card: Optional[str] = Field(None, max_length=200)
    donation_message: Optional[str] = Field(None, max_length=500)
    auto_accept_speakers: Optional[bool] = None


def _require_channel(room_id: int, db: Session) -> Room:
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    if not room.is_channel:
        raise HTTPException(400, "Стримы доступны только для каналов")
    return room


def _require_admin(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
    ).first()
    if not m or m.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Только владелец или админ канала может управлять стримом")
    return m


def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
    ).first()
    if not m:
        raise HTTPException(403, "Вы не участник этого канала")
    return m


async def _broadcast_stream(room_id: int, payload: dict, exclude: int | None = None):
    """Broadcast to all stream WS connections."""
    msg = _json.dumps(payload)
    for uid, ws in list(_stream_ws.get(room_id, {}).items()):
        if uid == exclude:
            continue
        try:
            await ws.send_text(msg)
        except Exception:
            _stream_ws.get(room_id, {}).pop(uid, None)


async def _notify_room_stream_state(room_id: int, action: str, stream: StreamState | None = None):
    """Notify room chat WS about stream state changes."""
    payload = {
        "type": "stream_update",
        "room_id": room_id,
        "action": action,
    }
    if stream:
        payload["stream"] = {
            "title": stream.title,
            "host_id": stream.host_id,
            "viewer_count": stream.viewer_count(),
            "started_at": stream.started_at,
        }
    await manager.broadcast_to_room(room_id, payload)

    # Global notification
    for uid in list(manager._global_ws.keys()):
        await manager.notify_user(uid, {
            "type": "stream_state",
            "room_id": room_id,
            "action": action,
            "is_live": action != "ended",
            "viewer_count": stream.viewer_count() if stream else 0,
        })


@router.post("/{room_id}/start", status_code=201)
async def start_stream(
    room_id: int,
    body: StartStreamRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Запуск стрима в канале. Только owner/admin."""
    _require_channel(room_id, db)
    _require_admin(room_id, u.id, db)

    if room_id in _active_streams:
        raise HTTPException(409, "Стрим уже запущен в этом канале")

    stream = StreamState(
        room_id=room_id,
        host=u,
        title=body.title or "Live",
        description=body.description,
        allow_reactions=body.allow_reactions,
        allow_donations=body.allow_donations,
        donation_card=body.donation_card,
        donation_message=body.donation_message,
        auto_accept_speakers=body.auto_accept_speakers,
    )
    _active_streams[room_id] = stream

    logger.info("Stream started in room %s by %s", room_id, u.username)
    await _notify_room_stream_state(room_id, "started", stream)

    return stream.to_dict()


@router.post("/{room_id}/stop")
async def stop_stream(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Остановка стрима. Только host или admin канала."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404, "Нет активного стрима")

    # Host or channel admin can stop
    member = _require_member(room_id, u.id, db)
    if u.id != stream.host_id and member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Только хост или админ может остановить стрим")

    # Notify all viewers
    await _broadcast_stream(room_id, {"type": "stream_ended", "ended_by": u.username})
    await _notify_room_stream_state(room_id, "ended")

    # Cleanup
    _active_streams.pop(room_id, None)
    _stream_ws.pop(room_id, None)

    logger.info("Stream stopped in room %s by %s", room_id, u.username)
    return {"ok": True, "viewer_peak": stream.viewer_peak}


@router.post("/{room_id}/join")
async def join_stream(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Присоединиться к стриму как зритель."""
    _require_member(room_id, u.id, db)
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404, "Нет активного стрима")

    if u.id in stream.participants:
        return {"joined": True, "already_in": True, "stream": stream.to_dict()}

    # Determine role
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == u.id,
    ).first()
    if member and member.role in (RoomRole.OWNER, RoomRole.ADMIN):
        role = StreamRole.CO_HOST
    else:
        role = StreamRole.VIEWER

    p = StreamParticipant(u, role)
    stream.participants[u.id] = p

    # Update peak
    count = stream.viewer_count()
    if count > stream.viewer_peak:
        stream.viewer_peak = count

    await _broadcast_stream(room_id, {
        "type": "stream_viewer_joined",
        "participant": p.to_dict(),
        "viewer_count": count,
    }, exclude=u.id)

    logger.info("Stream join: %s -> room %s (role=%s)", u.username, room_id, role.value)
    return {"joined": True, "already_in": False, "stream": stream.to_dict()}


@router.post("/{room_id}/leave")
async def leave_stream(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Покинуть стрим."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404, "Нет активного стрима")

    removed = stream.participants.pop(u.id, None)
    if not removed:
        raise HTTPException(400, "Вы не в стриме")

    # Remove from hand queue
    if u.id in stream.hand_queue:
        stream.hand_queue.remove(u.id)

    # If host leaves, end stream
    if u.id == stream.host_id:
        await _broadcast_stream(room_id, {"type": "stream_ended", "ended_by": u.username})
        await _notify_room_stream_state(room_id, "ended")
        _active_streams.pop(room_id, None)
        _stream_ws.pop(room_id, None)
        return {"left": True, "stream_ended": True}

    await _broadcast_stream(room_id, {
        "type": "stream_viewer_left",
        "user_id": u.id,
        "username": u.username,
        "viewer_count": stream.viewer_count(),
    })

    # Cleanup WS
    ws_room = _stream_ws.get(room_id, {})
    ws_room.pop(u.id, None)

    return {"left": True, "stream_ended": False}


@router.get("/{room_id}/status")
async def stream_status(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Статус стрима (есть ли активный)."""
    stream = _active_streams.get(room_id)
    if not stream:
        return {"is_live": False}
    return {"is_live": True, "stream": stream.to_dict()}


@router.post("/{room_id}/raise-hand")
async def raise_hand(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Зритель поднимает руку (запрос на выступление)."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404, "Нет активного стрима")

    p = stream.participants.get(u.id)
    if not p:
        raise HTTPException(400, "Вы не в стриме")

    if p.role in (StreamRole.HOST, StreamRole.CO_HOST):
        raise HTTPException(400, "Вы уже можете говорить")

    p.hand_raised = True
    if u.id not in stream.hand_queue:
        stream.hand_queue.append(u.id)

    # Auto-accept if configured
    if stream.auto_accept_speakers:
        p.can_speak = True
        p.can_video = True
        p.role = StreamRole.SPEAKER
        p.hand_raised = False
        stream.hand_queue = [uid for uid in stream.hand_queue if uid != u.id]
        await _broadcast_stream(room_id, {
            "type": "stream_permission_granted",
            "participant": p.to_dict(),
        })
        return {"hand_raised": False, "auto_accepted": True, "role": p.role.value}

    await _broadcast_stream(room_id, {
        "type": "stream_hand_raised",
        "user_id": u.id,
        "username": u.username,
        "display_name": p.display_name,
        "avatar_emoji": p.avatar_emoji,
        "avatar_url": p.avatar_url,
    })

    return {"hand_raised": True}


@router.post("/{room_id}/lower-hand")
async def lower_hand(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Зритель опускает руку."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404)

    p = stream.participants.get(u.id)
    if not p:
        raise HTTPException(400)

    p.hand_raised = False
    stream.hand_queue = [uid for uid in stream.hand_queue if uid != u.id]

    await _broadcast_stream(room_id, {
        "type": "stream_hand_lowered",
        "user_id": u.id,
    })

    return {"hand_raised": False}


@router.post("/{room_id}/permission")
async def grant_permission(
    room_id: int,
    body: GrantPermissionRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Управление правами участника стрима (host/co_host)."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404, "Нет активного стрима")

    # Only host/co_host can manage permissions
    actor = stream.participants.get(u.id)
    if not actor or actor.role not in (StreamRole.HOST, StreamRole.CO_HOST):
        raise HTTPException(403, "Только хост может управлять правами")

    target = stream.participants.get(body.user_id)
    if not target:
        raise HTTPException(404, "Участник не найден в стриме")

    # Can't change host permissions
    if target.role == StreamRole.HOST and u.id != stream.host_id:
        raise HTTPException(403, "Нельзя изменить права хоста")

    # Update role
    if body.role:
        new_role = StreamRole(body.role)
        target.role = new_role
        if new_role == StreamRole.SPEAKER:
            target.can_speak = True
            target.can_video = True
        elif new_role == StreamRole.CO_HOST:
            target.can_speak = True
            target.can_video = True
            target.can_screen_share = True
        elif new_role == StreamRole.VIEWER:
            target.can_speak = False
            target.can_video = False
            target.can_screen_share = False
            target.is_muted = True
            target.is_video_on = False

    # Granular permissions
    if body.can_speak is not None:
        target.can_speak = body.can_speak
        if not body.can_speak:
            target.is_muted = True
    if body.can_video is not None:
        target.can_video = body.can_video
        if not body.can_video:
            target.is_video_on = False
    if body.can_screen_share is not None:
        target.can_screen_share = body.can_screen_share

    # Clear hand if granted speaking
    if target.can_speak and target.hand_raised:
        target.hand_raised = False
        stream.hand_queue = [uid for uid in stream.hand_queue if uid != body.user_id]

    await _broadcast_stream(room_id, {
        "type": "stream_permission_granted",
        "participant": target.to_dict(),
        "granted_by": u.username,
    })

    return {"ok": True, "participant": target.to_dict()}


@router.post("/{room_id}/kick/{target_id}")
async def kick_from_stream(
    room_id: int,
    target_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Выгнать участника из стрима."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404)

    actor = stream.participants.get(u.id)
    if not actor or actor.role not in (StreamRole.HOST, StreamRole.CO_HOST):
        raise HTTPException(403, "Только хост может выгонять")

    if target_id == stream.host_id:
        raise HTTPException(403, "Нельзя выгнать хоста")

    removed = stream.participants.pop(target_id, None)
    if not removed:
        raise HTTPException(404, "Участник не найден")

    stream.hand_queue = [uid for uid in stream.hand_queue if uid != target_id]

    # Notify kicked user
    ws_room = _stream_ws.get(room_id, {})
    kicked_ws = ws_room.pop(target_id, None)
    if kicked_ws:
        try:
            await kicked_ws.send_text(_json.dumps({"type": "stream_kicked", "by": u.username}))
        except Exception:
            pass

    await _broadcast_stream(room_id, {
        "type": "stream_viewer_left",
        "user_id": target_id,
        "kicked": True,
        "viewer_count": stream.viewer_count(),
    })

    return {"ok": True}


@router.post("/{room_id}/reaction")
async def send_reaction(
    room_id: int,
    emoji: str = "❤️",
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отправить реакцию на стрим."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404)

    if not stream.allow_reactions:
        raise HTTPException(400, "Реакции отключены на этом стриме")

    if u.id not in stream.participants:
        raise HTTPException(400, "Вы не в стриме")

    # Sanitize emoji (max 10 chars)
    emoji = emoji[:10]
    stream.reaction_counts[emoji] = stream.reaction_counts.get(emoji, 0) + 1

    await _broadcast_stream(room_id, {
        "type": "stream_reaction",
        "emoji": emoji,
        "user_id": u.id,
        "username": u.username,
    })

    return {"ok": True}


@router.post("/{room_id}/donate")
async def send_donation(
    room_id: int,
    body: SendDonationRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отправить донат (сообщение отображается на стриме, оплата — внешняя)."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404)

    if not stream.allow_donations:
        raise HTTPException(400, "Донаты отключены на этом стриме")

    if u.id not in stream.participants:
        raise HTTPException(400, "Вы не в стриме")

    donation = {
        "user_id": u.id,
        "username": u.username,
        "display_name": stream.participants[u.id].display_name,
        "avatar_emoji": stream.participants[u.id].avatar_emoji,
        "amount": body.amount,
        "currency": body.currency,
        "message": body.message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    stream.donations.append(donation)

    await _broadcast_stream(room_id, {
        "type": "stream_donation",
        **donation,
    })

    return {"ok": True}


@router.put("/{room_id}/settings")
async def update_stream_settings(
    room_id: int,
    body: UpdateStreamRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Обновить настройки активного стрима."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404)

    actor = stream.participants.get(u.id)
    if not actor or actor.role not in (StreamRole.HOST, StreamRole.CO_HOST):
        raise HTTPException(403)

    if body.title is not None:
        stream.title = body.title
    if body.description is not None:
        stream.description = body.description
    if body.allow_reactions is not None:
        stream.allow_reactions = body.allow_reactions
    if body.allow_donations is not None:
        stream.allow_donations = body.allow_donations
    if body.donation_card is not None:
        stream.donation_card = body.donation_card
    if body.donation_message is not None:
        stream.donation_message = body.donation_message
    if body.auto_accept_speakers is not None:
        stream.auto_accept_speakers = body.auto_accept_speakers

    await _broadcast_stream(room_id, {
        "type": "stream_settings_updated",
        "stream": stream.to_dict(),
    })

    return stream.to_dict()


@router.get("/{room_id}/hands")
async def get_hand_queue(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Список поднятых рук."""
    stream = _active_streams.get(room_id)
    if not stream:
        raise HTTPException(404)

    hands = []
    for uid in stream.hand_queue:
        p = stream.participants.get(uid)
        if p and p.hand_raised:
            hands.append(p.to_dict())

    return {"hands": hands}


@ws_router.websocket("/ws/stream/{room_id}")
async def ws_stream(
    websocket: WebSocket,
    room_id: int,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    WebSocket для стрима: WebRTC сигналинг + real-time события.

    Типы сообщений (client → server):
      - stream_offer/stream_answer/stream_ice — WebRTC SDP/ICE
      - stream_mute — {is_muted, is_video_on}
      - stream_screen_share — {sharing: bool}
      - stream_reaction — {emoji}
      - stream_chat — {text} (стрим-чат)

    Типы сообщений (server → client):
      - stream_peers — список текущих участников
      - stream_peer_joined / stream_peer_left
      - stream_offer/answer/ice — relayed WebRTC
      - stream_permission_granted — обновление прав
      - stream_hand_raised / stream_hand_lowered
      - stream_reaction / stream_donation
      - stream_ended
    """
    from app.transport.knock import verify_knock, is_knock_required
    if is_knock_required():
        has_auth = bool(websocket.cookies.get("access_token"))
        if not has_auth:
            knock_token = websocket.query_params.get("knock") or websocket.cookies.get("_vk")
            if not verify_knock(knock_token):
                await websocket.close(code=1000)
                return

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

    stream = _active_streams.get(room_id)
    if not stream:
        await websocket.accept()
        await websocket.send_text(_json.dumps({"type": "stream_ended"}))
        await websocket.close(code=4404)
        return

    # Must be a participant (joined via REST)
    if user.id not in stream.participants:
        await websocket.accept()
        await websocket.close(code=4403)
        return

    await websocket.accept()
    _stream_ws.setdefault(room_id, {})[user.id] = websocket
    logger.info("Stream WS+ %s(%s) -> room %s", user.username, user.id, room_id)

    try:
        # Send current participants list
        peers = [p.to_dict() for uid, p in stream.participants.items() if uid != user.id]
        await websocket.send_text(_json.dumps({
            "type": "stream_peers",
            "peers": peers,
            "my_role": stream.participants[user.id].role.value,
            "stream": stream.to_dict(),
        }))

        # Notify others
        notify_msg = _json.dumps({
            "type": "stream_peer_joined",
            **stream.participants[user.id].to_dict(),
        })
        for uid, ws in list(_stream_ws.get(room_id, {}).items()):
            if uid != user.id:
                try:
                    await ws.send_text(notify_msg)
                except Exception:
                    _stream_ws.get(room_id, {}).pop(uid, None)

        # Message loop
        while True:
            raw = await websocket.receive_text()
            try:
                msg = _json.loads(raw)
            except Exception:
                continue

            msg_type = msg.get("type", "")
            participant = stream.participants.get(user.id)
            if not participant:
                break

            if msg_type in ("stream_offer", "stream_answer", "stream_ice"):
                # WebRTC signaling relay
                msg["from"] = user.id
                msg["username"] = user.username
                target = msg.get("to")
                if target and target in _stream_ws.get(room_id, {}):
                    try:
                        await _stream_ws[room_id][target].send_text(_json.dumps(msg))
                    except Exception:
                        _stream_ws.get(room_id, {}).pop(target, None)
                else:
                    # Broadcast (host sends to all viewers)
                    for uid, ws in list(_stream_ws.get(room_id, {}).items()):
                        if uid != user.id:
                            try:
                                await ws.send_text(_json.dumps(msg))
                            except Exception:
                                _stream_ws.get(room_id, {}).pop(uid, None)

            elif msg_type == "stream_mute":
                if participant.can_speak or msg.get("is_muted", True):
                    participant.is_muted = msg.get("is_muted", participant.is_muted)
                if participant.can_video:
                    participant.is_video_on = msg.get("is_video_on", participant.is_video_on)
                await _broadcast_stream(room_id, {
                    "type": "stream_mute",
                    "user_id": user.id,
                    "is_muted": participant.is_muted,
                    "is_video_on": participant.is_video_on,
                }, exclude=user.id)

            elif msg_type == "stream_screen_share":
                if not participant.can_screen_share:
                    await websocket.send_text(_json.dumps({
                        "type": "stream_error", "message": "Нет разрешения на демонстрацию экрана",
                    }))
                    continue
                participant.is_screen_sharing = msg.get("sharing", False)
                await _broadcast_stream(room_id, {
                    "type": "stream_screen_share",
                    "user_id": user.id,
                    "sharing": participant.is_screen_sharing,
                }, exclude=user.id)

            elif msg_type == "stream_reaction":
                if stream.allow_reactions:
                    emoji = str(msg.get("emoji", "❤️"))[:10]
                    stream.reaction_counts[emoji] = stream.reaction_counts.get(emoji, 0) + 1
                    await _broadcast_stream(room_id, {
                        "type": "stream_reaction",
                        "emoji": emoji,
                        "user_id": user.id,
                        "username": user.username,
                    }, exclude=user.id)

            elif msg_type == "stream_chat":
                text = str(msg.get("text", ""))[:500]
                if text:
                    await _broadcast_stream(room_id, {
                        "type": "stream_chat",
                        "user_id": user.id,
                        "username": user.username,
                        "display_name": participant.display_name,
                        "avatar_emoji": participant.avatar_emoji,
                        "text": text,
                    }, exclude=user.id)

    except WebSocketDisconnect:
        logger.debug("Stream WS disconnect user=%s room=%s", user.username, room_id)
    except Exception as e:
        logger.warning("Stream WS error user=%s room=%s: %s", user.username, room_id, e)
    finally:
        ws_room = _stream_ws.get(room_id, {})
        ws_room.pop(user.id, None)
        if not ws_room and room_id in _stream_ws:
            _stream_ws.pop(room_id, None)

        logger.info("Stream WS- %s(%s) <- room %s", user.username, user.id, room_id)

        # Auto-leave on disconnect
        stream = _active_streams.get(room_id)
        if stream and user.id in stream.participants:
            removed = stream.participants.pop(user.id, None)
            stream.hand_queue = [uid for uid in stream.hand_queue if uid != user.id]

            if user.id == stream.host_id:
                # Host disconnected — end stream
                await _broadcast_stream(room_id, {"type": "stream_ended", "ended_by": "disconnect"})
                await _notify_room_stream_state(room_id, "ended")
                _active_streams.pop(room_id, None)
                _stream_ws.pop(room_id, None)
            elif removed:
                await _broadcast_stream(room_id, {
                    "type": "stream_peer_left",
                    "user_id": user.id,
                    "username": user.username,
                    "viewer_count": stream.viewer_count(),
                })
