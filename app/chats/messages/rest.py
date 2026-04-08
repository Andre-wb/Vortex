"""
app/chats/messages/rest.py — REST API for messages (CRUD).

Endpoints:
  POST   /api/rooms/{room_id}/messages        — send a message
  GET    /api/rooms/{room_id}/messages         — list messages (paginated)
  PUT    /api/rooms/{room_id}/messages/{msg_id} — edit message
  DELETE /api/rooms/{room_id}/messages/{msg_id} — delete message
  POST   /api/rooms/{room_id}/messages/{msg_id}/react — add reaction
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.models import User
from app.models_rooms import Message, MessageType, Room, RoomMember, MessageReaction, MessageEditHistory

from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.security.crypto import hash_message
from app.security.sealed_sender import compute_sender_pseudo

from app.chats.messages._router import router, utc_iso

logger = logging.getLogger(__name__)


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class SendMessageBody(BaseModel):
    ciphertext: str
    reply_to: Optional[int] = None

class EditMessageBody(BaseModel):
    ciphertext: str

class ReactBody(BaseModel):
    emoji: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Не участник комнаты")
    return member


def _msg_dict(m: Message) -> dict:
    return {
        "id":          m.id,
        "msg_id":      m.id,
        "room_id":     m.room_id,
        "sender_pseudo": m.sender_pseudo,
        "sender":      m.sender.username if m.sender else None,
        "display_name": (m.sender.display_name or m.sender.username) if m.sender else None,
        "avatar_emoji": m.sender.avatar_emoji if m.sender else None,
        "avatar_url":   m.sender.avatar_url if m.sender else None,
        "ciphertext":  m.content_encrypted.hex() if isinstance(m.content_encrypted, (bytes, bytearray)) else str(m.content_encrypted or ""),
        "reply_to_id": m.reply_to_id,
        "thread_id":   m.thread_id,
        "is_edited":   m.is_edited,
        "created_at":  utc_iso(m.created_at),
    }


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/rooms/{room_id}/messages — send message
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/rooms/{room_id}/messages", status_code=201)
async def send_message(
    room_id: int,
    body: SendMessageBody,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Комната не найдена")

    _require_member(room_id, u.id, db)

    ciphertext_str = body.ciphertext.strip()
    if not ciphertext_str:
        raise HTTPException(422, "Пустой ciphertext")

    # Store as bytes (hex-decode if valid hex, otherwise encode as UTF-8)
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_str)
    except ValueError:
        ciphertext_bytes = ciphertext_str.encode("utf-8")

    content_hash = hash_message(ciphertext_bytes)
    if isinstance(content_hash, (bytes, bytearray)):
        content_hash = bytes(content_hash)

    reply_to_id = body.reply_to
    if reply_to_id:
        exists = db.query(Message.id).filter(
            Message.id == reply_to_id, Message.room_id == room_id,
        ).first()
        if not exists:
            reply_to_id = None

    msg = Message(
        room_id           = room_id,
        sender_pseudo     = compute_sender_pseudo(room_id, u.id),
        msg_type          = MessageType.TEXT,
        content_encrypted = ciphertext_bytes,
        content_hash      = content_hash,
        reply_to_id       = reply_to_id,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    # Broadcast to WS participants
    payload = {
        "type":          "message",
        "msg_id":        msg.id,
        "sender_id":     u.id,
        "sender_pseudo": msg.sender_pseudo,
        "sender":        u.username,
        "display_name":  u.display_name or u.username,
        "avatar_emoji":  u.avatar_emoji,
        "avatar_url":    u.avatar_url,
        "ciphertext":    ciphertext_str,
        "reply_to_id":   reply_to_id,
        "status":        "sent",
        "created_at":    utc_iso(msg.created_at),
    }
    await manager.broadcast_to_room(room_id, payload)

    return _msg_dict(msg)


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/rooms/{room_id}/messages — list messages (paginated)
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/rooms/{room_id}/messages")
async def list_messages(
    room_id:   int,
    before_id: Optional[int] = None,
    after_id:  Optional[int] = None,
    around_id: Optional[int] = None,
    limit:     int = 50,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Комната не найдена")

    _require_member(room_id, u.id, db)

    limit = max(1, min(limit, 200))

    # around_id: загружаем limit/2 до и limit/2 после указанного сообщения
    if around_id:
        half = limit // 2
        before = (
            db.query(Message).filter(
                Message.room_id == room_id,
                Message.thread_id.is_(None),
                Message.is_scheduled == False,
                Message.id <= around_id,
            ).order_by(Message.created_at.desc()).limit(half + 1).all()
        )
        after = (
            db.query(Message).filter(
                Message.room_id == room_id,
                Message.thread_id.is_(None),
                Message.is_scheduled == False,
                Message.id > around_id,
            ).order_by(Message.created_at.asc()).limit(half).all()
        )
        messages = list(reversed(before)) + after
        return {"messages": [_msg_dict(m) for m in messages]}

    q = db.query(Message).filter(
        Message.room_id == room_id,
        Message.thread_id.is_(None),
        Message.is_scheduled == False,
    )

    if before_id:
        q = q.filter(Message.id < before_id)
    if after_id:
        q = q.filter(Message.id > after_id)

    messages = q.order_by(Message.created_at.desc()).limit(limit).all()
    messages.reverse()

    return {"messages": [_msg_dict(m) for m in messages]}


# ══════════════════════════════════════════════════════════════════════════════
# PUT /api/rooms/{room_id}/messages/{msg_id} — edit message
# ══════════════════════════════════════════════════════════════════════════════

@router.put("/api/rooms/{room_id}/messages/{msg_id}")
async def edit_message(
    room_id: int,
    msg_id:  int,
    body: EditMessageBody,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_member(room_id, u.id, db)

    msg = db.query(Message).filter(
        Message.id == msg_id, Message.room_id == room_id,
    ).first()
    if not msg:
        raise HTTPException(404, "Сообщение не найдено")

    sender_pseudo = compute_sender_pseudo(room_id, u.id)
    if msg.sender_pseudo != sender_pseudo:
        raise HTTPException(403, "Только автор может редактировать")

    # Save edit history
    old_ciphertext = msg.content_encrypted.hex() if isinstance(msg.content_encrypted, (bytes, bytearray)) else str(msg.content_encrypted or "")
    db.add(MessageEditHistory(
        message_id    = msg.id,
        ciphertext_hex = old_ciphertext,
        edited_at     = datetime.now(timezone.utc),
    ))

    try:
        new_bytes = bytes.fromhex(body.ciphertext.strip())
    except ValueError:
        new_bytes = body.ciphertext.strip().encode("utf-8")

    msg.content_encrypted = new_bytes
    msg.is_edited = True
    msg.edited_at = datetime.now(timezone.utc)
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":       "edit",
        "msg_id":     msg.id,
        "ciphertext": body.ciphertext.strip(),
        "edited_at":  utc_iso(msg.edited_at),
    })

    return {"ok": True, "id": msg.id, "edited_at": utc_iso(msg.edited_at)}


# ══════════════════════════════════════════════════════════════════════════════
# DELETE /api/rooms/{room_id}/messages/{msg_id} — delete message
# ══════════════════════════════════════════════════════════════════════════════

@router.delete("/api/rooms/{room_id}/messages/{msg_id}")
async def delete_message(
    room_id: int,
    msg_id:  int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    member = _require_member(room_id, u.id, db)

    msg = db.query(Message).filter(
        Message.id == msg_id, Message.room_id == room_id,
    ).first()
    if not msg:
        raise HTTPException(404, "Сообщение не найдено")

    sender_pseudo = compute_sender_pseudo(room_id, u.id)
    from app.models_rooms import RoomRole
    is_owner = msg.sender_pseudo == sender_pseudo
    is_admin = member.role in (RoomRole.OWNER, RoomRole.ADMIN)

    if not is_owner and not is_admin:
        raise HTTPException(403, "Недостаточно прав для удаления")

    db.delete(msg)
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":   "delete",
        "msg_id": msg_id,
    })

    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/rooms/{room_id}/messages/{msg_id}/react — add reaction
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/rooms/{room_id}/messages/{msg_id}/react")
async def react_to_message(
    room_id: int,
    msg_id:  int,
    body: ReactBody,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_member(room_id, u.id, db)

    msg = db.query(Message).filter(
        Message.id == msg_id, Message.room_id == room_id,
    ).first()
    if not msg:
        raise HTTPException(404, "Сообщение не найдено")

    emoji = body.emoji.strip()[:10]
    if not emoji:
        raise HTTPException(422, "Пустой emoji")

    existing = db.query(MessageReaction).filter(
        MessageReaction.message_id == msg_id,
        MessageReaction.user_id == u.id,
        MessageReaction.emoji == emoji,
    ).first()

    if existing:
        db.delete(existing)
        db.commit()
        action = "remove"
    else:
        db.add(MessageReaction(message_id=msg_id, user_id=u.id, emoji=emoji))
        db.commit()
        action = "add"

    await manager.broadcast_to_room(room_id, {
        "type":     "reaction",
        "msg_id":   msg_id,
        "emoji":    emoji,
        "user_id":  u.id,
        "username": u.username,
        "action":   action,
    })

    return {"ok": True, "action": action}
