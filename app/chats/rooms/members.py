"""
rooms_members — Управление участниками комнаты: список, кик, роли, мут, бан.
"""
from __future__ import annotations

import logging

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import EncryptedRoomKey, PendingKeyRequest, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

from app.chats.rooms.helpers import (
    router,
    ChangeRoleRequest,
    _require_member,
)

logger = logging.getLogger(__name__)


@router.get("/{room_id}/members")
async def members(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    actor = _require_member(room_id, u.id, db)
    all_m = db.query(RoomMember).filter(RoomMember.room_id == room_id).all()

    # Участники с pending key requests
    pending_ids = {
        p.user_id for p in db.query(PendingKeyRequest).filter(
            PendingKeyRequest.room_id == room_id
        ).all()
    }

    return {
        "my_role": actor.role.value,
        "members": [{
            "user_id":      m.user_id,
            "username":     m.user.username      if m.user else "\u2014",
            "display_name": m.user.display_name  if m.user else "\u2014",
            "avatar_emoji": m.user.avatar_emoji  if m.user else "\U0001f464",
            "avatar_url":   m.user.avatar_url   if m.user else None,
            "role":         m.role.value,
            "is_online":    manager.is_online(room_id, m.user_id),
            "is_muted":     m.is_muted,
            "is_banned":    m.is_banned,
            "is_bot":       bool(m.user.is_bot) if m.user else False,
            "x25519_pubkey":m.user.x25519_public_key if m.user else None,
            "has_key":      m.user_id not in pending_ids,
        } for m in all_m],
    }


@router.post("/{room_id}/kick/{target_id}")
async def kick(
        room_id: int, target_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    actor = _require_member(room_id, u.id, db)
    if actor.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Недостаточно прав")

    t = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == target_id).first()
    if not t or t.role == RoomRole.OWNER:
        raise HTTPException(403)

    t.is_banned = True

    # Удаляем ключ кикнутого участника — он не должен иметь доступ к сообщениям
    db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == target_id,
        ).delete()

    db.commit()
    await manager.send_to_user(room_id, target_id, {"type": "kicked"})

    # Ротация ключа — кикнутый участник не сможет расшифровать новые сообщения
    db.query(EncryptedRoomKey).filter(EncryptedRoomKey.room_id == room_id).delete()
    db.commit()
    await manager.broadcast_to_room(room_id, {"type": "key_rotated"})
    logger.info(f"Room key rotated after kick in room {room_id}")

    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Управление ролями и модерация участников
# ══════════════════════════════════════════════════════════════════════════════

@router.put("/{room_id}/members/{target_id}/role")
async def change_member_role(
        room_id: int, target_id: int,
        body: ChangeRoleRequest,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Изменить роль участника. Только OWNER может назначать/снимать админов."""
    actor = _require_member(room_id, u.id, db)
    if actor.role != RoomRole.OWNER:
        raise HTTPException(403, "Только владелец может менять роли")

    if target_id == u.id:
        raise HTTPException(400, "Нельзя изменить свою роль")

    t = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == target_id).first()
    if not t:
        raise HTTPException(404, "Участник не найден")
    if t.role == RoomRole.OWNER:
        raise HTTPException(403, "Нельзя изменить роль владельца")

    new_role = RoomRole.ADMIN if body.role == "admin" else RoomRole.MEMBER
    t.role = new_role
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type": "member_updated",
        "user_id": target_id,
        "role": new_role.value,
    })
    logger.info(f"Role changed: user {target_id} -> {new_role.value} in room {room_id} by {u.username}")

    return {"ok": True, "role": new_role.value}


@router.put("/{room_id}/members/{target_id}/mute")
async def toggle_mute_member(
        room_id: int, target_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Заглушить / разглушить участника. ADMIN и OWNER могут мутить."""
    actor = _require_member(room_id, u.id, db)
    if actor.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Недостаточно прав")

    if target_id == u.id:
        raise HTTPException(400, "Нельзя заглушить себя")

    t = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == target_id).first()
    if not t:
        raise HTTPException(404, "Участник не найден")
    if t.role == RoomRole.OWNER:
        raise HTTPException(403, "Нельзя заглушить владельца")
    if t.role == RoomRole.ADMIN and actor.role != RoomRole.OWNER:
        raise HTTPException(403, "Только владелец может заглушить админа")

    t.is_muted = not t.is_muted
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type": "member_updated",
        "user_id": target_id,
        "is_muted": t.is_muted,
    })
    logger.info(f"Mute toggled: user {target_id} is_muted={t.is_muted} in room {room_id} by {u.username}")

    return {"ok": True, "is_muted": t.is_muted}


@router.put("/{room_id}/members/{target_id}/ban")
async def toggle_ban_member(
        room_id: int, target_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Забанить / разбанить участника. ADMIN и OWNER могут банить."""
    actor = _require_member(room_id, u.id, db)
    if actor.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Недостаточно прав")

    if target_id == u.id:
        raise HTTPException(400, "Нельзя забанить себя")

    t = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == target_id).first()
    if not t:
        raise HTTPException(404, "Участник не найден")
    if t.role == RoomRole.OWNER:
        raise HTTPException(403, "Нельзя забанить владельца")
    if t.role == RoomRole.ADMIN and actor.role != RoomRole.OWNER:
        raise HTTPException(403, "Только владелец может забанить админа")

    t.is_banned = not t.is_banned
    db.commit()

    if t.is_banned:
        # Удаляем ключ забаненного участника
        db.query(EncryptedRoomKey).filter(
            EncryptedRoomKey.room_id == room_id,
            EncryptedRoomKey.user_id == target_id,
        ).delete()
        db.commit()
        await manager.send_to_user(room_id, target_id, {"type": "kicked"})

    await manager.broadcast_to_room(room_id, {
        "type": "member_updated",
        "user_id": target_id,
        "is_banned": t.is_banned,
    })
    logger.info(f"Ban toggled: user {target_id} is_banned={t.is_banned} in room {room_id} by {u.username}")

    return {"ok": True, "is_banned": t.is_banned}
