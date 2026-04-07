"""
rooms_theme — Темы комнат: установка, получение, сброс, принятие/отклонение DM-тем.
"""
from __future__ import annotations

import json as _json
import logging

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Room, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

from app.chats.rooms.helpers import (
    router,
    RoomThemeBody,
    _require_member,
    _validate_theme,
)

logger = logging.getLogger(__name__)


@router.put("/{room_id}/theme")
async def set_room_theme(
        room_id: int,
        body: RoomThemeBody,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Установить тему комнаты.
    - Для обычных комнат/каналов/групп: только OWNER/ADMIN.
    - Для DM: любой из двух участников может предложить тему.
      Первый вызов сохраняет тему и рассылает theme_proposal через WS.
      Второй участник может принять (повторный PUT с тем же телом) или отклонить (DELETE).
    """
    m = _require_member(room_id, u.id, db)
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)

    theme_str = _validate_theme(body)

    if r.is_dm:
        # For DMs: save directly (either participant can set)
        r.theme_json = theme_str
        db.commit()
        # Broadcast theme change to the other participant
        await manager.broadcast_to_room(room_id, {
            "type": "theme_proposal",
            "theme": _json.loads(theme_str),
            "proposed_by": u.id,
            "proposed_by_name": u.display_name or u.username,
            "room_id": room_id,
        })
        return {"ok": True, "theme": _json.loads(theme_str)}
    else:
        # Regular rooms/channels/groups: admin/owner only
        if m.role not in (RoomRole.OWNER, RoomRole.ADMIN):
            raise HTTPException(403, "Недостаточно прав для изменения темы")
        r.theme_json = theme_str
        db.commit()
        await manager.broadcast_to_room(room_id, {
            "type": "theme_changed",
            "theme": _json.loads(theme_str),
            "room_id": room_id,
        })
        return {"ok": True, "theme": _json.loads(theme_str)}


@router.get("/{room_id}/theme")
async def get_room_theme(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Получить тему комнаты."""
    _require_member(room_id, u.id, db)
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)
    theme = _json.loads(r.theme_json) if r.theme_json else None
    return {"theme": theme}


@router.delete("/{room_id}/theme")
async def reset_room_theme(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Сбросить тему комнаты к умолчанию."""
    m = _require_member(room_id, u.id, db)
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)

    if r.is_dm:
        # Any DM participant can reset
        pass
    elif m.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Недостаточно прав")

    r.theme_json = None
    db.commit()
    await manager.broadcast_to_room(room_id, {
        "type": "theme_changed",
        "theme": None,
        "room_id": room_id,
    })
    return {"ok": True}


@router.post("/{room_id}/theme/accept")
async def accept_dm_theme(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Принять предложенную тему в DM."""
    _require_member(room_id, u.id, db)
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r or not r.is_dm:
        raise HTTPException(400, "Только для DM")
    if not r.theme_json:
        raise HTTPException(400, "Нет предложенной темы")
    # Theme is already saved — just notify acceptance
    await manager.broadcast_to_room(room_id, {
        "type": "theme_accepted",
        "theme": _json.loads(r.theme_json),
        "accepted_by": u.id,
        "room_id": room_id,
    })
    return {"ok": True, "theme": _json.loads(r.theme_json)}


@router.post("/{room_id}/theme/reject")
async def reject_dm_theme(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Отклонить предложенную тему в DM (сбрасывает к умолчанию)."""
    _require_member(room_id, u.id, db)
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r or not r.is_dm:
        raise HTTPException(400, "Только для DM")
    r.theme_json = None
    db.commit()
    await manager.broadcast_to_room(room_id, {
        "type": "theme_rejected",
        "rejected_by": u.id,
        "room_id": room_id,
    })
    return {"ok": True}
