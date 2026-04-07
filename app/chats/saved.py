"""
app/chats/saved.py — Избранные (сохранённые) сообщения.

Позволяет пользователю добавлять сообщения из любого чата в личное избранное
и просматривать их в едином списке. Сервер хранит только ссылку на сообщение —
зашифрованный контент расшифровывается клиентом.

Endpoints:
  POST   /api/saved/{message_id}  — toggle: сохранить / убрать из избранного
  GET    /api/saved               — список всех сохранённых (по saved_at desc)
  DELETE /api/saved/{message_id}  — убрать из избранного
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Message, Room, SavedMessage
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/saved", tags=["saved"])


@router.post("/{message_id}")
async def toggle_saved(
    message_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Toggle: если сообщение уже в избранном — убирает, иначе добавляет."""
    existing = db.query(SavedMessage).filter(
        SavedMessage.user_id == u.id,
        SavedMessage.message_id == message_id,
    ).first()

    if existing:
        db.delete(existing)
        db.commit()
        return {"saved": False, "message_id": message_id}

    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(404, "Сообщение не найдено")

    sm = SavedMessage(
        user_id=u.id,
        message_id=message_id,
        room_id=msg.room_id,
    )
    db.add(sm)
    db.commit()
    return {"saved": True, "message_id": message_id}


@router.get("")
async def list_saved(
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Возвращает все сохранённые сообщения текущего пользователя."""
    rows = (
        db.query(SavedMessage, Message, Room)
        .join(Message, SavedMessage.message_id == Message.id)
        .join(Room, Message.room_id == Room.id)
        .filter(SavedMessage.user_id == u.id)
        .order_by(SavedMessage.saved_at.desc())
        .all()
    )

    result = []
    for sm, msg, room in rows:
        sender = None
        if msg.sender:
            sender = {
                "id": msg.sender.id,
                "username": msg.sender.username,
                "display_name": msg.sender.display_name or msg.sender.username,
            }
        result.append({
            "id":         sm.id,
            "message_id": msg.id,
            "room_id":    msg.room_id,
            "room_name":  room.name,
            "sender":     sender,
            "msg_type":   msg.msg_type.value if msg.msg_type else "text",
            "ciphertext": msg.content_encrypted.hex() if msg.content_encrypted else None,
            "file_name":  msg.file_name,
            "created_at": msg.created_at.isoformat() if msg.created_at else None,
            "saved_at":   sm.saved_at.isoformat() if sm.saved_at else None,
        })
    return {"saved": result}


@router.delete("/{message_id}")
async def unsave_message(
    message_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Убирает сообщение из избранного."""
    sm = db.query(SavedMessage).filter(
        SavedMessage.user_id == u.id,
        SavedMessage.message_id == message_id,
    ).first()
    if not sm:
        raise HTTPException(404, "Сообщение не в избранном")
    db.delete(sm)
    db.commit()
    return {"removed": True, "message_id": message_id}


@router.get("/check/{message_id}")
async def check_saved(
    message_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Проверяет, сохранено ли сообщение в избранном."""
    exists = db.query(SavedMessage).filter(
        SavedMessage.user_id == u.id,
        SavedMessage.message_id == message_id,
    ).first() is not None
    return {"saved": exists, "message_id": message_id}
