"""
app/chats/chat.py — E2E WebSocket чат. Сервер ретранслирует шифротекст, не расшифровывает.

Sub-modules (extracted for maintainability):
  chat_push.py        — Web Push subscriptions & delivery
  chat_polls.py       — In-room polls (create / vote)
  chat_schedule.py    — Scheduled & timed (self-destructing) messages
  chat_moderation.py  — Auto-delete, slow-mode, mute, pin, export
  chat_files.py       — File upload / download / listing
  chat_ws_signal.py   — WebRTC signalling WS & global notifications WS
  chat_flood.py       — Flood detection (auto-mute / auto-ban)
  chat_keys.py        — E2E room key delivery & key responses
  chat_messages.py    — E2E message, thread reply, edit, delete handlers
  chat_actions.py     — mark_read, reactions, forward, pin_message handlers
  chat_history.py     — Message history delivery on WS connect
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import (
    Depends, HTTPException,
    WebSocket, WebSocketDisconnect,
)
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import (
    Message, Room, RoomMember,
)

from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user, get_user_ws

# ── Shared router (all sub-modules register on this same instance) ────────────
from app.chats.messages._router import router, utc_iso, parse_client_ts, check_double_extension, DANGEROUS_EXTS  # noqa: F401

# ── Sub-module imports (triggers @router.xxx() registrations) ─────────────────
import app.chats.messages.push        # noqa: F401  – /api/push/subscribe
import app.chats.messages.moderation  # noqa: F401  – auto-delete, slow-mode, mute, pin, export
import app.chats.messages.files       # noqa: F401  – /api/files/upload|download|room
import app.chats.messages.ws_signal   # noqa: F401  – /ws/signal, /ws/notifications

# ── Sub-module handler imports (called from ws_chat dispatch) ─────────────────
from app.chats.messages.polls import (
    handle_create_poll, handle_vote_poll,
    handle_retract_vote, handle_close_poll, handle_suggest_option,
)
from app.chats.messages.schedule import (
    handle_timed_message, handle_schedule_message,
    deliver_scheduled_messages, cleanup_expired_messages,
)

from app.chats.messages.keys import (
    deliver_or_request_room_key as _deliver_or_request_room_key,
    notify_pending_key_requests as _notify_pending_key_requests,
    handle_key_response as _handle_key_response,
)
from app.chats.messages.messages import (
    handle_e2e_message as _handle_e2e_message,
    handle_thread_reply as _handle_thread_reply,
    handle_edit_message as _handle_edit_message,
    handle_delete_message as _handle_delete_message,
)
from app.chats.messages.actions import (
    handle_mark_read as _handle_mark_read,
    handle_reaction as _handle_reaction,
    handle_forward as _handle_forward,
    handle_pin_message as _handle_pin_message,
)
from app.chats.messages.history import send_history as _send_history

# Aliases used in ws_chat dispatch and legacy callers
_handle_create_poll      = handle_create_poll
_handle_vote_poll        = handle_vote_poll
_handle_retract_vote     = handle_retract_vote
_handle_close_poll       = handle_close_poll
_handle_suggest_option   = handle_suggest_option
_handle_timed_message    = handle_timed_message
_handle_schedule_message = handle_schedule_message

logger = logging.getLogger(__name__)

# backward-compat aliases used by main.py cleanup loop
_utc_iso = utc_iso
_parse_client_ts = parse_client_ts
_check_double_extension = check_double_extension
_DANGEROUS_EXTS = DANGEROUS_EXTS


# ══════════════════════════════════════════════════════════════════════════════
# REST: пометить комнату как прочитанную
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/rooms/{room_id}/read")
async def mark_room_read(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отмечает все сообщения в комнате как прочитанные."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник")

    last_msg = (
        db.query(Message.id)
        .filter(Message.room_id == room_id)
        .order_by(Message.id.desc())
        .first()
    )
    if last_msg:
        member.last_read_message_id = last_msg[0]
        db.commit()

    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# REST: получить сообщения треда
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/rooms/{room_id}/thread/{msg_id}")
async def get_thread_messages(
    room_id: int,
    msg_id:  int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Возвращает все сообщения треда (где thread_id == msg_id), включая корневое."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник")

    # Корневое сообщение
    root = db.query(Message).filter(
        Message.id == msg_id, Message.room_id == room_id,
    ).first()
    if not root:
        raise HTTPException(404, "Сообщение не найдено")

    # Ответы в треде
    replies = (
        db.query(Message)
        .filter(Message.thread_id == msg_id, Message.room_id == room_id)
        .order_by(Message.id.asc())
        .limit(200)
        .all()
    )

    def _msg_to_dict(m: Message) -> dict:
        d = m.to_relay_dict()
        d["sender"]       = m.sender.username      if m.sender else "\u2014"
        d["display_name"] = (m.sender.display_name or m.sender.username) if m.sender else "\u2014"
        d["avatar_emoji"] = m.sender.avatar_emoji   if m.sender else "\U0001F464"
        d["avatar_url"]   = m.sender.avatar_url     if m.sender else None
        return d

    return {
        "root":    _msg_to_dict(root),
        "replies": [_msg_to_dict(r) for r in replies],
    }


@router.get("/api/rooms/{room_id}/messages/{msg_id}/history")
async def get_message_edit_history(
    room_id: int,
    msg_id:  int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Возвращает историю редактирований сообщения (предыдущие версии)."""
    from app.models_rooms import MessageEditHistory

    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник")

    msg = db.query(Message).filter(
        Message.id == msg_id, Message.room_id == room_id,
    ).first()
    if not msg:
        raise HTTPException(404, "Сообщение не найдено")

    history = (
        db.query(MessageEditHistory)
        .filter(MessageEditHistory.message_id == msg_id)
        .order_by(MessageEditHistory.edited_at.asc())
        .all()
    )

    return {
        "msg_id": msg_id,
        "current": {
            "ciphertext_hex": msg.content_encrypted.hex() if isinstance(msg.content_encrypted, (bytes, bytearray)) else str(msg.content_encrypted or ""),
            "edited_at": msg.edited_at.isoformat() if msg.edited_at else None,
        },
        "history": [
            {"ciphertext_hex": h.ciphertext_hex, "edited_at": h.edited_at.isoformat()}
            for h in history
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# REST: Web Push подписка
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# E2E WebSocket чат
# ══════════════════════════════════════════════════════════════════════════════

@router.websocket("/ws/{room_id:int}")
async def ws_chat(
        websocket: WebSocket,
        room_id:   int,
        token:     Optional[str] = None,
        db:        Session       = Depends(get_db),
):
    # Anti-probing: knock sequence в global mode
    from app.transport.knock import verify_knock, is_knock_required
    if is_knock_required():
        # Users with valid auth cookie bypass knock (DPI probes don't have cookies)
        has_auth = bool(websocket.cookies.get("access_token"))
        if not has_auth:
            knock_token = websocket.query_params.get("knock") or websocket.cookies.get("_vk")
            if not verify_knock(knock_token):
                # Don't accept — DPI probe gets nothing
                await websocket.close(code=1000)
                return

    # Аутентификация через cookie или query-param токен
    try:
        raw_token = websocket.cookies.get("access_token") or token
        if not raw_token:
            await websocket.accept()
            await websocket.close(code=4401)
            return
        user = await get_user_ws(raw_token, db)
    except HTTPException:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
        RoomMember.is_banned == False,
        ).first()
    if not member:
        await websocket.accept()
        await websocket.close(code=4403)
        return

    await manager.connect(
        room_id, user.id, user.username,
        user.display_name or user.username,
        user.avatar_emoji, websocket,
        )

    try:
        await _deliver_or_request_room_key(room_id, user, db)
        await _send_history(room_id, user.id, db)
        await manager.send_to_user(room_id, user.id, {
            "type":  "online",
            "users": manager.get_online_users(room_id),
        })
        await _notify_pending_key_requests(room_id, user.id, db)

        while True:
            raw = await websocket.receive_text()
            if len(raw) > 65536:  # 64 KB max message
                await websocket.send_json({"error": "Message too large"})
                continue
            data   = json.loads(raw)
            action = data.get("action", "")

            if action == "message":
                await _handle_e2e_message(room_id, user, data, db)

            elif action == "edit_message":
                await _handle_edit_message(room_id, user, data, db)

            elif action == "delete_message":
                await _handle_delete_message(room_id, user, data, db)

            elif action == "key_response":
                await _handle_key_response(room_id, user, data, db)

            elif action == "typing":
                await manager.set_typing(room_id, user.id, bool(data.get("is_typing")))

            elif action == "file_sending":
                await manager.broadcast_to_room(room_id, {
                    "type":         "file_sending",
                    "sender":       user.username,
                    "display_name": user.display_name or user.username,
                    "filename":     data.get("filename", ""),
                }, exclude=user.id)

            elif action == "stop_file_sending":
                await manager.broadcast_to_room(room_id, {
                    "type":   "stop_file_sending",
                    "sender": user.username,
                }, exclude=user.id)

            elif action == "signal":
                await _handle_signal(room_id, user, data, db)

            elif action == "ping":
                await manager.send_to_user(room_id, user.id, {"type": "pong"})

            elif action == "mark_read":
                await _handle_mark_read(room_id, user, data, db)

            elif action == "react":
                await _handle_reaction(room_id, user, data, db)

            elif action == "forward":
                await _handle_forward(room_id, user, data, db)

            elif action == "pin_message":
                await _handle_pin_message(room_id, user, data, db)

            elif action == "timed_message":
                await _handle_timed_message(room_id, user, data, db)

            elif action == "create_poll":
                await _handle_create_poll(room_id, user, data, db)

            elif action == "vote_poll":
                await _handle_vote_poll(room_id, user, data, db)

            elif action == "retract_vote":
                await _handle_retract_vote(room_id, user, data, db)

            elif action == "close_poll":
                await _handle_close_poll(room_id, user, data, db)

            elif action == "suggest_option":
                await _handle_suggest_option(room_id, user, data, db)

            elif action == "schedule_message":
                await _handle_schedule_message(room_id, user, data, db)

            elif action == "thread_reply":
                await _handle_thread_reply(room_id, user, data, db)

            elif action == "screenshot":
                await manager.broadcast_to_room(room_id, {
                    "type":     "screenshot_taken",
                    "user_id":  user.id,
                    "username": user.display_name or user.username,
                }, exclude=user.id)

    except WebSocketDisconnect:
        logger.debug("WS disconnect user=%s room=%s", user.username, room_id)
    except Exception as e:
        logger.warning(f"WS error user={user.username} room={room_id}: {e}")
    finally:
        await manager.disconnect(room_id, user.id)


# ══════════════════════════════════════════════════════════════════════════════
# WebRTC сигнализация
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_signal(room_id: int, user: User, data: dict, db: Session = None) -> None:
    payload = {k: v for k, v in data.items() if k != "action"}
    payload["type"]     = "signal"
    payload["from"]     = user.id
    payload["username"] = user.username

    # Targeted signaling: if "to" is specified, send only to that user (for group calls)
    target_uid = data.get("to")
    if target_uid:
        await manager.send_to_user(room_id, target_uid, payload)
    else:
        await manager.broadcast_to_room(room_id, payload, exclude=user.id)

    # При входящем звонке (invite) — уведомляем участников через notification WS
    signal_type = data.get("type", "")
    if signal_type == "invite" and db:
        room_obj = db.query(Room).filter(Room.id == room_id).first()
        room_members = db.query(RoomMember.user_id).filter(
            RoomMember.room_id == room_id,
            RoomMember.is_banned == False,
        ).all()
        online_in_room = set(manager._rooms.get(room_id, {}).keys())
        for (member_id,) in room_members:
            if member_id != user.id and member_id not in online_in_room:
                await manager.notify_user(member_id, {
                    "type":             "incoming_call",
                    "room_id":          room_id,
                    "room_name":        room_obj.name if room_obj else "",
                    "is_dm":            room_obj.is_dm if room_obj else False,
                    "caller_id":        user.id,
                    "caller_username":  user.username,
                    "caller_display_name": user.display_name or user.username,
                    "caller_avatar":    user.avatar_emoji,
                    "caller_avatar_url": user.avatar_url,
                    "has_video":        data.get("hasVideo", False),
                })

    try:
        from app.federation.federation import relay
        if relay.get_room(room_id) is not None:
            await relay.send_to_remote(room_id, payload)
    except Exception as e:
        logger.warning(f"Signal relay forward failed room={room_id}: {e}")
