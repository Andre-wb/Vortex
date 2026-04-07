"""
app/chats/chat_moderation.py — Room moderation REST endpoints:
auto-delete timer, slow mode, mute toggle, pin message, chat export.
"""
from __future__ import annotations

import logging

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.chats.messages._router import router, utc_iso
from app.database import get_db
from app.models import User
from app.models_rooms import Message, Room, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)


# ── Auto-delete ───────────────────────────────────────────────────────────────

class _AutoDeleteRequest(BaseModel):
    seconds: int = 0  # 0 = disabled


@router.post("/api/rooms/{room_id}/auto-delete")
async def set_auto_delete(
    room_id: int,
    body: _AutoDeleteRequest,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Устанавливает таймер автоудаления для всех новых сообщений в комнате."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member or member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Недостаточно прав")

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404)

    room.auto_delete_seconds = body.seconds if body.seconds > 0 else None
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":    "auto_delete_changed",
        "seconds": body.seconds,
    })
    return {"ok": True}


# ── Slow mode ─────────────────────────────────────────────────────────────────

class _SlowModeRequest(BaseModel):
    seconds: int = 0  # 0 = disabled


@router.post("/api/rooms/{room_id}/slow-mode")
async def set_slow_mode(
    room_id: int,
    body: _SlowModeRequest,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Устанавливает медленный режим для комнаты."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member or member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Недостаточно прав")

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404)

    room.slow_mode_seconds = max(0, body.seconds)
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":    "slow_mode_changed",
        "seconds": room.slow_mode_seconds,
    })
    return {"ok": True}


# ── Room mute toggle ──────────────────────────────────────────────────────────

@router.post("/api/rooms/{room_id}/mute")
async def toggle_mute(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Переключает мьют уведомлений для комнаты."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник")

    member.is_muted = not member.is_muted
    db.commit()
    return {"muted": member.is_muted}


# ── Pin message ───────────────────────────────────────────────────────────────

class _PinRequest(BaseModel):
    msg_id: int | None = None


@router.post("/api/rooms/{room_id}/pin")
async def pin_message_rest(
    room_id: int,
    body: _PinRequest,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Закрепляет/открепляет сообщение через REST."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member or member.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Недостаточно прав")

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404)

    if body.msg_id:
        msg = db.query(Message.id).filter(
            Message.id == body.msg_id, Message.room_id == room_id
        ).first()
        if not msg:
            raise HTTPException(404, "Сообщение не найдено")

    room.pinned_message_id = body.msg_id
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":   "message_pinned",
        "msg_id": body.msg_id,
    })
    return {"ok": True}


@router.get("/api/rooms/{room_id}/pinned")
async def get_pinned_messages(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Возвращает список закреплённых сообщений в комнате."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник")

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404)

    pinned = []
    if room.pinned_message_id:
        msg = db.query(Message).filter(
            Message.id == room.pinned_message_id,
            Message.room_id == room_id,
        ).first()
        if msg:
            pinned.append({
                "id":         msg.id,
                "sender_id":  msg.sender_id,
                "sender":     msg.sender.username if msg.sender else "—",
                "msg_type":   msg.msg_type.value,
                "created_at": utc_iso(msg.created_at),
            })

    return {"room_id": room_id, "pinned": pinned}


# ── Drafts ────────────────────────────────────────────────────────────────────

# In-memory draft storage (per user per room).
_drafts: dict[tuple[int, int], str] = {}


class _DraftRequest(BaseModel):
    text: str


@router.post("/api/rooms/{room_id}/draft")
async def save_draft(
    room_id: int,
    body: _DraftRequest,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Сохраняет черновик сообщения."""
    _drafts[(u.id, room_id)] = body.text
    return {"ok": True, "room_id": room_id}


@router.get("/api/rooms/{room_id}/draft")
async def get_draft(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Возвращает черновик сообщения."""
    text = _drafts.get((u.id, room_id), "")
    return {"room_id": room_id, "text": text}


@router.delete("/api/rooms/{room_id}/draft")
async def clear_draft(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Удаляет черновик сообщения."""
    _drafts.pop((u.id, room_id), None)
    return {"ok": True}


# ── Chat export ───────────────────────────────────────────────────────────────

@router.get("/api/rooms/{room_id}/export")
async def export_chat(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Экспорт истории чата как JSON (зашифрованные сообщения — клиент расшифрует)."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник")

    messages = db.query(Message).filter(
        Message.room_id == room_id,
        Message.is_scheduled == False,
    ).order_by(Message.created_at).all()

    export = [
        {
            "id":         m.id,
            "sender_id":  m.sender_id,
            "sender":     m.sender.username if m.sender else "—",
            "msg_type":   m.msg_type.value,
            "ciphertext": m.content_encrypted.hex() if m.content_encrypted else None,
            "file_name":  m.file_name,
            "created_at": utc_iso(m.created_at),
            "is_edited":  m.is_edited,
        }
        for m in messages
    ]

    return {"room_id": room_id, "message_count": len(export), "messages": export}
