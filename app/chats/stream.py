from __future__ import annotations

import asyncio
import contextlib
import json as _json
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.chats import live_backend as _live
from app.chats.messages.core import ws_origin_ok  # shared CSWSH guard
from app.database import get_db
from app.models import User
from app.models_rooms import Room, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user, get_user_ws

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stream", tags=["stream"])
ws_router = APIRouter(tags=["stream"])


# room_id -> {user_id -> WS}   (stream WS connections)
_stream_ws: dict[int, dict[int, WebSocket]] = {}
_schedule_checker_task = None  # asyncio background task


async def _check_scheduled_streams():
    """Фоновая задача: проверяет запланированные стримы каждые 5 сек.

    Цикл крутится во всех воркерах, но само срабатывание захватывается одной
    операцией общего стора, поэтому стрим стартует ровно один раз."""
    while True:
        try:
            while True:
                due = _live.schedule_claim_due()
                if not due:
                    break
                host_id = due.get("host_id")
                if not host_id:
                    continue
                if _live.stream_status(due["room_id"]):
                    continue
                from app.config import Config

                if not Config.BMP_DELIVERY_ENABLED:
                    await manager.notify_user(
                        host_id,
                        {
                            "type": "stream_auto_start",
                            "room_id": due["room_id"],
                            "title": due.get("title", "Live"),
                        },
                    )
                logger.debug("Stream auto-start scheduled (sanitized)")
        except Exception as e:
            logger.warning("_check_scheduled_streams error: %s", e)
        await asyncio.sleep(5)


def start_schedule_checker():
    """Запуск фоновой задачи проверки расписания. Вызывается из main.py startup."""
    global _schedule_checker_task

    if _schedule_checker_task is None or _schedule_checker_task.done():
        _schedule_checker_task = asyncio.create_task(_check_scheduled_streams())


class ScheduleStreamRequest(BaseModel):
    title: str = Field("Live", max_length=200)
    scheduled_at: str = Field(..., max_length=50)


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
        raise HTTPException(400, "Streams are only available for channels")
    return room


def _require_admin(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not m or m.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Only channel owner or admin can manage streams")
    return m


def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not m:
        raise HTTPException(403, "You are not a member of this channel")
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


async def _notify_room_stream_state(room_id: int, action: str, stream: dict | None = None):
    """Notify room chat WS about stream state changes."""
    payload = {
        "type": "stream_update",
        "room_id": room_id,
        "action": action,
    }
    if stream:
        payload["stream"] = {
            "title": stream["title"],
            "host_id": stream["host_id"],
            "viewer_count": stream["viewer_count"],
            "started_at": stream["started_at"],
        }
    await manager.broadcast_to_room(room_id, payload)

    # Global notification
    for uid in list(manager._global_ws.keys()):
        await manager.notify_user(
            uid,
            {
                "type": "stream_state",
                "room_id": room_id,
                "action": action,
                "is_live": action != "ended",
                "viewer_count": stream["viewer_count"] if stream else 0,
            },
        )


def _require_stream(room_id: int) -> dict:
    stream = _live.stream_status(room_id)
    if not stream:
        raise HTTPException(404, "No active stream")
    return stream


def _viewer_count(room_id: int) -> int:
    watching = _live.stream_status(room_id)
    return watching["viewer_count"] if watching else 0


def _renew_stream(room_id: int) -> None:
    with contextlib.suppress(_live.LiveUnavailableError):
        _live.stream_renew(room_id)


@router.post("/{room_id}/schedule")
async def schedule_stream(
    room_id: int,
    body: ScheduleStreamRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Запланировать стрим. Уведомляет всех подписчиков канала."""
    _require_channel(room_id, db)
    _require_admin(room_id, u.id, db)

    planned = _live.schedule_plan(
        room_id, body.title, body.scheduled_at, u.id, u.display_name or u.username
    )
    if not planned:
        raise HTTPException(400, "scheduled_at is not a moment the server can read")

    # Notify all room members via room WS + global notifications
    room = db.query(Room).filter(Room.id == room_id).first()
    room_name = room.name if room else ""
    payload = {
        "type": "stream_scheduled",
        "room_id": room_id,
        "room_name": room_name,
        "title": body.title,
        "scheduled_at": body.scheduled_at,
        "host_name": u.display_name or u.username,
    }
    await manager.broadcast_to_room(room_id, payload)

    # Also notify via global WS so users not in the room see browser notifications
    members = (
        db.query(RoomMember.user_id)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.is_banned.is_(False),
        )
        .all()
    )
    for (uid,) in members:
        if uid != u.id:
            await manager.notify_user(uid, payload)

    logger.info("Stream scheduled in room %s at %s by %s", room_id, body.scheduled_at, u.username)
    return {"ok": True, "scheduled_at": body.scheduled_at}


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

    opened = _live.stream_open(
        room_id,
        u,
        body.title,
        body.description,
        body.allow_reactions,
        body.allow_donations,
        body.donation_card,
        body.donation_message,
        body.auto_accept_speakers,
    )
    if opened["status"] == "already_live":
        raise HTTPException(409, "Stream already started in this channel")

    stream = opened["stream"]
    _live.schedule_forget(room_id)

    logger.info("Stream started in room %s by %s", room_id, u.username)
    await _notify_room_stream_state(room_id, "started", stream)

    return stream


@router.post("/{room_id}/stop")
async def stop_stream(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Остановка стрима. Только host или admin канала."""
    stream = _require_stream(room_id)

    # Host or channel admin can stop
    member = _require_member(room_id, u.id, db)
    if u.id != stream["host_id"] and member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Only host or admin can stop the stream")

    # Notify all viewers
    await _broadcast_stream(room_id, {"type": "stream_ended", "ended_by": u.username})
    await _notify_room_stream_state(room_id, "ended")

    # Cleanup
    stopped = _live.stream_stop(room_id)
    _stream_ws.pop(room_id, None)

    logger.info("Stream stopped in room %s by %s", room_id, u.username)
    return {"ok": True, "viewer_peak": stopped["viewer_peak"]}


@router.post("/{room_id}/join")
async def join_stream(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Присоединиться к стриму как зритель."""
    _require_member(room_id, u.id, db)

    member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == u.id,
        )
        .first()
    )
    runs_the_room = bool(member and member.role in (RoomRole.OWNER, RoomRole.ADMIN))

    seated = _live.stream_join(room_id, u, runs_the_room)
    if seated["status"] == "missing":
        raise HTTPException(404, "No active stream")

    stream = seated["stream"]
    if seated["already_in"]:
        return {"joined": True, "already_in": True, "stream": stream}

    joined = next(p for p in stream["participants"] if p["user_id"] == u.id)
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_viewer_joined",
            "participant": joined,
            "viewer_count": stream["viewer_count"],
        },
        exclude=u.id,
    )

    logger.info("Stream join: %s -> room %s (role=%s)", u.username, room_id, joined["role"])
    return {"joined": True, "already_in": False, "stream": stream}


@router.post("/{room_id}/leave")
async def leave_stream(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Покинуть стрим."""
    left = _live.stream_leave(room_id, u.id)
    if left["status"] == "missing":
        raise HTTPException(404, "No active stream")
    if left["status"] == "not_in":
        raise HTTPException(400, "You are not in the stream")

    # If host leaves, end stream
    if left["stream_ended"]:
        await _broadcast_stream(room_id, {"type": "stream_ended", "ended_by": u.username})
        await _notify_room_stream_state(room_id, "ended")
        _stream_ws.pop(room_id, None)
        return {"left": True, "stream_ended": True}

    watching = _live.stream_status(room_id)
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_viewer_left",
            "user_id": u.id,
            "username": u.username,
            "viewer_count": watching["viewer_count"] if watching else 0,
        },
    )

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
    stream = _live.stream_status(room_id)
    if not stream:
        sched = _live.schedule_find(room_id)
        if sched:
            return {"is_live": False, "scheduled": sched}
        return {"is_live": False}
    return {"is_live": True, "stream": stream}


@router.post("/{room_id}/raise-hand")
async def raise_hand(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Зритель поднимает руку (запрос на выступление)."""
    raised = _live.stream_raise_hand(room_id, u.id)
    if raised["status"] == "missing":
        raise HTTPException(404, "No active stream")
    if raised["status"] == "not_in":
        raise HTTPException(400, "You are not in the stream")
    if raised["status"] == "already_speaks":
        raise HTTPException(400, "You can already speak")

    if raised["status"] == "auto_accepted":
        participant = raised["participant"]
        await _broadcast_stream(
            room_id,
            {
                "type": "stream_permission_granted",
                "participant": participant,
            },
        )
        return {"hand_raised": False, "auto_accepted": True, "role": participant["role"]}

    p = _live.stream_status(room_id)
    standing = next(
        (held for held in p["participants"] if held["user_id"] == u.id), None
    ) if p else None
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_hand_raised",
            "user_id": u.id,
            "username": u.username,
            "display_name": standing["display_name"] if standing else u.username,
            "avatar_emoji": standing["avatar_emoji"] if standing else u.avatar_emoji,
            "avatar_url": standing["avatar_url"] if standing else u.avatar_url,
        },
    )

    return {"hand_raised": True}


@router.post("/{room_id}/lower-hand")
async def lower_hand(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Зритель опускает руку."""
    lowered = _live.stream_lower_hand(room_id, u.id)
    if lowered["status"] == "missing":
        raise HTTPException(404)
    if lowered["status"] == "not_in":
        raise HTTPException(400)

    await _broadcast_stream(
        room_id,
        {
            "type": "stream_hand_lowered",
            "user_id": u.id,
        },
    )

    return {"hand_raised": False}


@router.post("/{room_id}/permission")
async def grant_permission(
    room_id: int,
    body: GrantPermissionRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Управление правами участника стрима (host/co_host)."""
    granted = _live.stream_grant(
        room_id,
        u.id,
        body.user_id,
        body.role,
        body.can_speak,
        body.can_video,
        body.can_screen_share,
    )
    if granted["status"] == "missing":
        raise HTTPException(404, "No active stream")
    if granted["status"] == "not_allowed":
        raise HTTPException(403, "Only host can manage permissions")
    if granted["status"] == "no_such_participant":
        raise HTTPException(404, "Participant not found in stream")

    participant = granted["participant"]
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_permission_granted",
            "participant": participant,
            "granted_by": u.username,
        },
    )

    return {"ok": True, "participant": participant}


@router.post("/{room_id}/kick/{target_id}")
async def kick_from_stream(
    room_id: int,
    target_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Выгнать участника из стрима."""
    kicked = _live.stream_kick(room_id, u.id, target_id)
    if kicked["status"] == "missing":
        raise HTTPException(404)
    if kicked["status"] == "not_allowed":
        raise HTTPException(403, "Only host can kick participants")
    if kicked["status"] == "cannot_kick_host":
        raise HTTPException(403, "Cannot kick the host")
    if kicked["status"] == "no_such_participant":
        raise HTTPException(404, "Participant not found")

    # Notify kicked user
    ws_room = _stream_ws.get(room_id, {})
    kicked_ws = ws_room.pop(target_id, None)
    if kicked_ws:
        with contextlib.suppress(Exception):
            await kicked_ws.send_text(_json.dumps({"type": "stream_kicked", "by": u.username}))

    watching = _live.stream_status(room_id)
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_viewer_left",
            "user_id": target_id,
            "kicked": True,
            "viewer_count": watching["viewer_count"] if watching else 0,
        },
    )

    return {"ok": True}


@router.post("/{room_id}/reaction")
async def send_reaction(
    room_id: int,
    emoji: str = "❤️",
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отправить реакцию на стрим."""
    reacted = _live.stream_react(room_id, u.id, emoji)
    if reacted["status"] == "missing":
        raise HTTPException(404)
    if reacted["status"] == "disabled":
        raise HTTPException(400, "Reactions are disabled for this stream")
    if reacted["status"] == "not_in":
        raise HTTPException(400, "You are not in the stream")

    emoji = reacted["emoji"]
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_reaction",
            "emoji": emoji,
            "user_id": u.id,
            "username": u.username,
        },
    )

    return {"ok": True}


@router.post("/{room_id}/donate")
async def send_donation(
    room_id: int,
    body: SendDonationRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отправить донат (сообщение отображается на стриме, оплата — внешняя)."""
    donated = _live.stream_donate(room_id, u.id, body.amount, body.currency, body.message)
    if donated["status"] == "missing":
        raise HTTPException(404)
    if donated["status"] == "disabled":
        raise HTTPException(400, "Donations are disabled for this stream")
    if donated["status"] == "not_in":
        raise HTTPException(400, "You are not in the stream")

    await _broadcast_stream(
        room_id,
        {
            "type": "stream_donation",
            **donated["donation"],
        },
    )

    return {"ok": True}


@router.put("/{room_id}/settings")
async def update_stream_settings(
    room_id: int,
    body: UpdateStreamRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Обновить настройки активного стрима."""
    updated = _live.stream_update(
        room_id,
        u.id,
        title=body.title,
        description=body.description,
        allow_reactions=body.allow_reactions,
        allow_donations=body.allow_donations,
        donation_card=body.donation_card,
        donation_message=body.donation_message,
        auto_accept_speakers=body.auto_accept_speakers,
    )
    if updated["status"] == "missing":
        raise HTTPException(404)
    if updated["status"] == "not_allowed":
        raise HTTPException(403)

    stream = updated["stream"]
    await _broadcast_stream(
        room_id,
        {
            "type": "stream_settings_updated",
            "stream": stream,
        },
    )

    return stream


@router.get("/{room_id}/hands")
async def get_hand_queue(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Список поднятых рук."""
    hands = _live.stream_hands(room_id)
    if hands is None:
        raise HTTPException(404)

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
    # reject cross-site WS origins (CSWSH) before any processing.
    if not ws_origin_ok(websocket):
        await websocket.accept()
        await websocket.close(code=4403)
        return

    from app.transport.knock import is_knock_required, verify_knock

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

    stream = _live.stream_status(room_id)
    if not stream:
        await websocket.accept()
        await websocket.send_text(_json.dumps({"type": "stream_ended"}))
        await websocket.close(code=4404)
        return

    # Must be a participant (joined via REST)
    seated = {held["user_id"]: held for held in stream["participants"]}
    if user.id not in seated:
        await websocket.accept()
        await websocket.close(code=4403)
        return

    await websocket.accept()
    _stream_ws.setdefault(room_id, {})[user.id] = websocket
    logger.info("Stream WS+ %s(%s) -> room %s", user.username, user.id, room_id)

    pending = None
    try:
        # Send current participants list
        peers = [held for uid, held in seated.items() if uid != user.id]
        await websocket.send_text(
            _json.dumps(
                {
                    "type": "stream_peers",
                    "peers": peers,
                    "my_role": seated[user.id]["role"],
                    "stream": stream,
                }
            )
        )

        # Notify others
        notify_msg = _json.dumps(
            {
                "type": "stream_peer_joined",
                **seated[user.id],
            }
        )
        for uid, ws in list(_stream_ws.get(room_id, {}).items()):
            if uid != user.id:
                try:
                    await ws.send_text(notify_msg)
                except Exception:
                    _stream_ws.get(room_id, {}).pop(uid, None)

        # Message loop
        renew_at = time.monotonic() + _live.RENEWAL_SECONDS
        pending = asyncio.ensure_future(websocket.receive_text())
        while True:
            arrived, _waiting = await asyncio.wait(
                {pending}, timeout=_live.RENEWAL_SECONDS
            )
            if time.monotonic() >= renew_at:
                _renew_stream(room_id)
                renew_at = time.monotonic() + _live.RENEWAL_SECONDS
            if not arrived:
                continue

            raw = pending.result()
            pending = asyncio.ensure_future(websocket.receive_text())

            try:
                msg = _json.loads(raw)
            except Exception:  # noqa: S112
                continue

            msg_type = msg.get("type", "")

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
                amended = _live.stream_mute(
                    room_id, user.id, msg.get("is_muted"), msg.get("is_video_on")
                )
                if amended["status"] != "ok":
                    break
                participant = amended["participant"]
                await _broadcast_stream(
                    room_id,
                    {
                        "type": "stream_mute",
                        "user_id": user.id,
                        "is_muted": participant["is_muted"],
                        "is_video_on": participant["is_video_on"],
                    },
                    exclude=user.id,
                )

            elif msg_type == "stream_screen_share":
                shared = _live.stream_share_screen(
                    room_id, user.id, bool(msg.get("sharing", False))
                )
                if shared["status"] == "not_allowed":
                    await websocket.send_text(
                        _json.dumps(
                            {
                                "type": "stream_error",
                                "message": "Screen sharing permission denied",
                            }
                        )
                    )
                    continue
                if shared["status"] != "ok":
                    break
                await _broadcast_stream(
                    room_id,
                    {
                        "type": "stream_screen_share",
                        "user_id": user.id,
                        "sharing": shared["participant"]["is_screen_sharing"],
                    },
                    exclude=user.id,
                )

            elif msg_type == "stream_reaction":
                reacted = _live.stream_react(room_id, user.id, str(msg.get("emoji", "❤️")))
                if reacted["status"] == "ok":
                    await _broadcast_stream(
                        room_id,
                        {
                            "type": "stream_reaction",
                            "emoji": reacted["emoji"],
                            "user_id": user.id,
                            "username": user.username,
                        },
                        exclude=user.id,
                    )

            elif msg_type == "stream_chat":
                text = str(msg.get("text", ""))[:500]
                if text:
                    await _broadcast_stream(
                        room_id,
                        {
                            "type": "stream_chat",
                            "user_id": user.id,
                            "username": user.username,
                            "display_name": seated[user.id]["display_name"],
                            "avatar_emoji": seated[user.id]["avatar_emoji"],
                            "text": text,
                        },
                        exclude=user.id,
                    )

    except WebSocketDisconnect:
        logger.debug("Stream WS disconnect user=%s room=%s", user.username, room_id)
    except Exception as e:
        logger.warning("Stream WS error user=%s room=%s: %s", user.username, room_id, e)
    finally:
        if pending is not None and not pending.done():
            pending.cancel()

        ws_room = _stream_ws.get(room_id, {})
        ws_room.pop(user.id, None)
        if not ws_room and room_id in _stream_ws:
            _stream_ws.pop(room_id, None)

        logger.info("Stream WS- %s(%s) <- room %s", user.username, user.id, room_id)

        # Auto-leave on disconnect
        left = {"status": "missing"}
        with contextlib.suppress(_live.LiveUnavailableError):
            left = _live.stream_leave(room_id, user.id)
        if left["status"] == "ok":
            if left["stream_ended"]:
                # Host disconnected — end stream
                await _broadcast_stream(room_id, {"type": "stream_ended", "ended_by": "disconnect"})
                await _notify_room_stream_state(room_id, "ended")
                _stream_ws.pop(room_id, None)
            else:
                await _broadcast_stream(
                    room_id,
                    {
                        "type": "stream_peer_left",
                        "user_id": user.id,
                        "username": user.username,
                        "viewer_count": _viewer_count(room_id),
                    },
                )
