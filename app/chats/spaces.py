"""
app/chats/spaces.py — Пространства (Spaces).

Space — контейнер, группирующий несколько комнат/каналов/голосовых каналов
под единым членством и правами доступа (аналог Discord-сервера).

Ключевые принципы:
  - При вступлении в Space пользователь автоматически добавляется во ВСЕ комнаты Space.
  - При выходе из Space пользователь удаляется из ВСЕХ комнат Space.
  - При создании новой комнаты в Space все участники Space автоматически добавляются в неё.
  - Категории (SpaceCategory) служат для визуальной группировки комнат.
"""
from __future__ import annotations

import logging
import os
import secrets as _secrets
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import (
    EncryptedRoomKey, PendingKeyRequest, Room, RoomMember, RoomRole,
    Space, SpaceCategory, SpaceMember,
)
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.utilites.utils import generative_invite_code

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/spaces", tags=["spaces"])


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic-схемы
# ══════════════════════════════════════════════════════════════════════════════

class SpaceCreate(BaseModel):
    name:        str  = Field(..., min_length=1, max_length=100)
    description: str  = Field("", max_length=500)
    is_public:   bool = False


class SpaceUpdate(BaseModel):
    name:         Optional[str]  = Field(None, min_length=1, max_length=100)
    description:  Optional[str]  = Field(None, max_length=500)
    avatar_emoji: Optional[str]  = Field(None, max_length=10)
    is_public:    Optional[bool] = None


class JoinByCode(BaseModel):
    invite_code: str = Field(..., min_length=1, max_length=16)


class CategoryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)


class CategoryUpdate(BaseModel):
    name:      Optional[str] = Field(None, min_length=1, max_length=50)
    order_idx: Optional[int] = None


class SpaceRoomCreate(BaseModel):
    name:        str            = Field(..., min_length=1, max_length=100)
    description: str            = Field("", max_length=500)
    is_voice:    bool           = False
    is_channel:  bool           = False
    category_id: Optional[int]  = None


class ChangeRoleBody(BaseModel):
    role: str = Field(..., pattern="^(admin|member)$")


# ══════════════════════════════════════════════════════════════════════════════
# Вспомогательные функции
# ══════════════════════════════════════════════════════════════════════════════

def _space_dict(s: Space) -> dict:
    return {
        "id":           s.id,
        "name":         s.name,
        "description":  s.description or "",
        "avatar_emoji": s.avatar_emoji or "🏠",
        "avatar_url":   s.avatar_url,
        "creator_id":   s.creator_id,
        "invite_code":  s.invite_code,
        "is_public":    s.is_public,
        "member_count": s.member_count,
        "created_at":   s.created_at.isoformat(),
        "theme_json":   s.theme_json,
    }


def _require_space(space_id: int, db: Session) -> Space:
    s = db.query(Space).filter(Space.id == space_id).first()
    if not s:
        raise HTTPException(404, "Пространство не найдено")
    return s


def _require_space_member(space_id: int, user_id: int, db: Session) -> SpaceMember:
    m = db.query(SpaceMember).filter(
        SpaceMember.space_id == space_id,
        SpaceMember.user_id == user_id,
    ).first()
    if not m:
        raise HTTPException(403, "Вы не участник этого пространства")
    return m


def _require_admin(space_id: int, user_id: int, db: Session) -> SpaceMember:
    m = _require_space_member(space_id, user_id, db)
    if m.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Недостаточно прав")
    return m


def _require_owner(space_id: int, user_id: int, db: Session) -> SpaceMember:
    m = _require_space_member(space_id, user_id, db)
    if m.role != RoomRole.OWNER:
        raise HTTPException(403, "Только владелец может выполнить это действие")
    return m


def _add_user_to_room(room: Room, user_id: int, role: RoomRole, db: Session) -> None:
    """Добавляет пользователя в комнату (если ещё не участник)."""
    existing = db.query(RoomMember).filter(
        RoomMember.room_id == room.id,
        RoomMember.user_id == user_id,
    ).first()
    if existing:
        return
    db.add(RoomMember(room_id=room.id, user_id=user_id, role=role))


def _remove_user_from_room(room_id: int, user_id: int, db: Session) -> None:
    """Удаляет пользователя из комнаты и очищает его ключи."""
    db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
    ).delete()
    db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == user_id,
    ).delete()
    db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id == user_id,
    ).delete()


def _get_default_category(space_id: int, db: Session) -> SpaceCategory:
    """Возвращает категорию с наименьшим order_idx (дефолтную)."""
    cat = (db.query(SpaceCategory)
           .filter(SpaceCategory.space_id == space_id)
           .order_by(SpaceCategory.order_idx)
           .first())
    return cat


# ══════════════════════════════════════════════════════════════════════════════
# CRUD пространств
# ══════════════════════════════════════════════════════════════════════════════

@router.post("", status_code=201)
async def create_space(
        body: SpaceCreate,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Создаёт новое пространство.

    Автоматически создаются:
      - Категория по умолчанию "Основное"
      - Текстовая комната #general
      - Голосовая комната #голосовой
    Создатель становится OWNER пространства и всех комнат.
    """
    space = Space(
        name        = body.name.strip()[:100],
        description = body.description.strip()[:500] if body.description else "",
        creator_id  = u.id,
        invite_code = generative_invite_code(8),
        is_public   = body.is_public,
        member_count = 1,
    )
    db.add(space)
    db.flush()

    # Владелец
    db.add(SpaceMember(space_id=space.id, user_id=u.id, role=RoomRole.OWNER))

    # Категория по умолчанию
    default_cat = SpaceCategory(space_id=space.id, name="Основное", order_idx=0)
    db.add(default_cat)
    db.flush()

    # Комната #general (текстовая)
    general = Room(
        name        = "general",
        description = "Основной текстовый канал",
        creator_id  = u.id,
        invite_code = generative_invite_code(8),
        space_id    = space.id,
        category_id = default_cat.id,
        order_idx   = 0,
        avatar_emoji = "💬",
    )
    db.add(general)
    db.flush()
    db.add(RoomMember(room_id=general.id, user_id=u.id, role=RoomRole.OWNER))

    # Комната #голосовой (голосовая)
    voice = Room(
        name        = "голосовой",
        description = "Голосовой канал",
        creator_id  = u.id,
        invite_code = generative_invite_code(8),
        is_voice    = True,
        space_id    = space.id,
        category_id = default_cat.id,
        order_idx   = 1,
        avatar_emoji = "🔊",
    )
    db.add(voice)
    db.flush()
    db.add(RoomMember(room_id=voice.id, user_id=u.id, role=RoomRole.OWNER))

    db.commit()
    db.refresh(space)

    logger.info(f"Space created: '{space.name}' (id={space.id}) by {u.username}")

    return {
        **_space_dict(space),
        "default_rooms": [
            {"id": general.id, "name": general.name, "is_voice": False},
            {"id": voice.id,   "name": voice.name,   "is_voice": True},
        ],
    }


@router.get("")
async def my_spaces(
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Список пространств, в которых текущий пользователь является участником."""
    memberships = db.query(SpaceMember).filter(SpaceMember.user_id == u.id).all()
    space_ids = [m.space_id for m in memberships]
    if not space_ids:
        return {"spaces": []}

    role_map = {m.space_id: m.role.value for m in memberships}
    spaces = db.query(Space).filter(Space.id.in_(space_ids)).order_by(Space.created_at.desc()).all()

    return {"spaces": [
        {**_space_dict(s), "my_role": role_map.get(s.id)}
        for s in spaces
    ]}


@router.get("/public")
async def public_spaces(db: Session = Depends(get_db)):
    """Публичные пространства для обзора."""
    spaces = (db.query(Space)
              .filter(Space.is_public == True)
              .order_by(Space.member_count.desc())
              .limit(50)
              .all())
    return {"spaces": [_space_dict(s) for s in spaces]}


@router.get("/{space_id}")
async def get_space(
        space_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Детали пространства: информация, комнаты сгруппированные по категориям, участники."""
    space = _require_space(space_id, db)
    member = _require_space_member(space_id, u.id, db)

    # Категории
    cats = (db.query(SpaceCategory)
            .filter(SpaceCategory.space_id == space_id)
            .order_by(SpaceCategory.order_idx)
            .all())

    # Комнаты
    rooms = (db.query(Room)
             .filter(Room.space_id == space_id)
             .order_by(Room.order_idx)
             .all())

    from app.chats.rooms import _room_dict

    # Группируем комнаты по категориям
    cat_rooms: dict[int | None, list] = {c.id: [] for c in cats}
    cat_rooms[None] = []  # комнаты без категории
    for r in rooms:
        bucket = r.category_id if r.category_id in cat_rooms else None
        cat_rooms[bucket].append(_room_dict(r))

    categories_data = []
    for c in cats:
        categories_data.append({
            "id":        c.id,
            "name":      c.name,
            "order_idx": c.order_idx,
            "rooms":     cat_rooms.get(c.id, []),
        })
    # Комнаты без категории
    if cat_rooms[None]:
        categories_data.append({
            "id":        None,
            "name":      "Без категории",
            "order_idx": 9999,
            "rooms":     cat_rooms[None],
        })

    return {
        **_space_dict(space),
        "my_role":    member.role.value,
        "categories": categories_data,
    }


@router.put("/{space_id}")
async def update_space(
        space_id: int,
        body: SpaceUpdate,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Обновить информацию о пространстве (owner/admin)."""
    _require_admin(space_id, u.id, db)
    space = _require_space(space_id, db)

    if body.name is not None:
        space.name = body.name.strip()[:100]
    if body.description is not None:
        space.description = body.description.strip()[:500]
    if body.avatar_emoji is not None:
        space.avatar_emoji = body.avatar_emoji[:10]
    if body.is_public is not None:
        space.is_public = body.is_public

    db.commit()
    db.refresh(space)
    logger.info(f"Space {space_id} updated by {u.username}")
    return _space_dict(space)


@router.delete("/{space_id}")
async def delete_space(
        space_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Удалить пространство и все его комнаты (только owner)."""
    _require_owner(space_id, u.id, db)
    space = _require_space(space_id, db)

    # Уведомляем участников всех комнат
    rooms = db.query(Room).filter(Room.space_id == space_id).all()
    for r in rooms:
        await manager.broadcast_to_room(r.id, {"type": "room_deleted"})

    # Удаляем все комнаты пространства (каскад удалит RoomMember, сообщения и т.д.)
    for r in rooms:
        db.delete(r)

    # Удаляем само пространство (каскад удалит SpaceMember, SpaceCategory)
    db.delete(space)
    db.commit()

    logger.info(f"Space {space_id} deleted by {u.username}")
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Членство в пространстве
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{space_id}/join")
async def join_space_by_body(
        space_id: int,
        body: JoinByCode,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Вступить в пространство по invite_code (передаётся в теле запроса)."""
    space = _require_space(space_id, db)
    if space.invite_code.upper() != body.invite_code.strip().upper():
        raise HTTPException(403, "Неверный код приглашения")
    return await _join_space(space, u, db)


@router.post("/join/{invite_code}")
async def join_space_by_url(
        invite_code: str,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Вступить в пространство по invite_code (URL-friendly)."""
    space = db.query(Space).filter(Space.invite_code == invite_code.upper()).first()
    if not space:
        raise HTTPException(404, "Пространство не найдено")
    return await _join_space(space, u, db)


async def _join_space(space: Space, u: User, db: Session) -> dict:
    """Внутренняя логика вступления в пространство."""
    existing = db.query(SpaceMember).filter(
        SpaceMember.space_id == space.id,
        SpaceMember.user_id == u.id,
    ).first()
    if existing:
        return {"joined": False, "space": _space_dict(space), "message": "Вы уже участник"}

    # Добавляем в пространство
    db.add(SpaceMember(space_id=space.id, user_id=u.id, role=RoomRole.MEMBER))
    space.member_count = (space.member_count or 0) + 1

    # Добавляем во ВСЕ комнаты пространства
    rooms = db.query(Room).filter(Room.space_id == space.id).all()
    for r in rooms:
        _add_user_to_room(r, u.id, RoomRole.MEMBER, db)

    db.commit()

    logger.info(f"{u.username} joined space '{space.name}' (id={space.id}), added to {len(rooms)} rooms")

    return {
        "joined": True,
        "space":  _space_dict(space),
        "rooms_joined": len(rooms),
    }


@router.post("/{space_id}/leave")
async def leave_space(
        space_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Покинуть пространство. Удаляет из всех комнат пространства."""
    space = _require_space(space_id, db)
    member = db.query(SpaceMember).filter(
        SpaceMember.space_id == space_id,
        SpaceMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(404, "Вы не участник этого пространства")

    # Если владелец уходит и он единственный — удаляем пространство
    if member.role == RoomRole.OWNER:
        remaining = db.query(SpaceMember).filter(
            SpaceMember.space_id == space_id,
            SpaceMember.user_id != u.id,
        ).count()
        if remaining == 0:
            # Удаляем всё пространство
            rooms = db.query(Room).filter(Room.space_id == space_id).all()
            for r in rooms:
                await manager.broadcast_to_room(r.id, {"type": "room_deleted"})
                db.delete(r)
            db.delete(space)
            db.commit()
            logger.info(f"Space {space_id} deleted (owner left, no remaining members)")
            return {"left": True, "space_deleted": True}

    # Удаляем из всех комнат пространства
    rooms = db.query(Room).filter(Room.space_id == space_id).all()
    for r in rooms:
        _remove_user_from_room(r.id, u.id, db)

    # Удаляем из пространства
    db.delete(member)
    space.member_count = max(0, (space.member_count or 1) - 1)

    db.commit()

    logger.info(f"{u.username} left space '{space.name}' (id={space_id})")

    return {"left": True, "space_deleted": False}


@router.get("/{space_id}/members")
async def space_members(
        space_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Список участников пространства с ролями."""
    _require_space(space_id, db)
    actor = _require_space_member(space_id, u.id, db)

    members = db.query(SpaceMember).filter(SpaceMember.space_id == space_id).all()

    return {
        "my_role": actor.role.value,
        "members": [{
            "user_id":      m.user_id,
            "username":     m.user.username     if m.user else "—",
            "display_name": m.user.display_name if m.user else "—",
            "avatar_emoji": m.user.avatar_emoji if m.user else "👤",
            "avatar_url":   m.user.avatar_url   if m.user else None,
            "role":         m.role.value,
            "joined_at":    m.joined_at.isoformat() if m.joined_at else None,
        } for m in members],
    }


@router.put("/{space_id}/members/{target_id}/role")
async def change_space_member_role(
        space_id: int,
        target_id: int,
        body: ChangeRoleBody,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Изменить роль участника пространства (только owner)."""
    _require_owner(space_id, u.id, db)

    if target_id == u.id:
        raise HTTPException(400, "Нельзя изменить свою роль")

    target = db.query(SpaceMember).filter(
        SpaceMember.space_id == space_id,
        SpaceMember.user_id == target_id,
    ).first()
    if not target:
        raise HTTPException(404, "Участник не найден")
    if target.role == RoomRole.OWNER:
        raise HTTPException(403, "Нельзя изменить роль владельца")

    new_role = RoomRole.ADMIN if body.role == "admin" else RoomRole.MEMBER
    target.role = new_role
    db.commit()

    logger.info(f"Space {space_id}: role changed for user {target_id} -> {new_role.value} by {u.username}")
    return {"ok": True, "role": new_role.value}


@router.delete("/{space_id}/members/{target_id}")
async def kick_space_member(
        space_id: int,
        target_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Исключить участника из пространства (admin/owner). Удаляет из всех комнат."""
    actor = _require_admin(space_id, u.id, db)

    if target_id == u.id:
        raise HTTPException(400, "Нельзя исключить себя")

    target = db.query(SpaceMember).filter(
        SpaceMember.space_id == space_id,
        SpaceMember.user_id == target_id,
    ).first()
    if not target:
        raise HTTPException(404, "Участник не найден")
    if target.role == RoomRole.OWNER:
        raise HTTPException(403, "Нельзя исключить владельца")
    if target.role == RoomRole.ADMIN and actor.role != RoomRole.OWNER:
        raise HTTPException(403, "Только владелец может исключить админа")

    space = _require_space(space_id, db)

    # Удаляем из всех комнат пространства
    rooms = db.query(Room).filter(Room.space_id == space_id).all()
    for r in rooms:
        _remove_user_from_room(r.id, target_id, db)
        await manager.send_to_user(r.id, target_id, {"type": "kicked"})

    # Удаляем из пространства
    db.delete(target)
    space.member_count = max(0, (space.member_count or 1) - 1)

    db.commit()

    logger.info(f"User {target_id} kicked from space {space_id} by {u.username}")
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Категории
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{space_id}/categories", status_code=201)
async def create_category(
        space_id: int,
        body: CategoryCreate,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Создать категорию в пространстве (admin/owner)."""
    _require_admin(space_id, u.id, db)
    _require_space(space_id, db)

    max_order = (db.query(SpaceCategory)
                 .filter(SpaceCategory.space_id == space_id)
                 .count())
    cat = SpaceCategory(
        space_id  = space_id,
        name      = body.name.strip()[:50],
        order_idx = max_order,
    )
    db.add(cat)
    db.commit()
    db.refresh(cat)

    logger.info(f"Category '{cat.name}' created in space {space_id} by {u.username}")
    return {"id": cat.id, "name": cat.name, "order_idx": cat.order_idx}


@router.put("/{space_id}/categories/{cat_id}")
async def update_category(
        space_id: int,
        cat_id: int,
        body: CategoryUpdate,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Переименовать/переупорядочить категорию (admin/owner)."""
    _require_admin(space_id, u.id, db)

    cat = db.query(SpaceCategory).filter(
        SpaceCategory.id == cat_id,
        SpaceCategory.space_id == space_id,
    ).first()
    if not cat:
        raise HTTPException(404, "Категория не найдена")

    if body.name is not None:
        cat.name = body.name.strip()[:50]
    if body.order_idx is not None:
        cat.order_idx = body.order_idx

    db.commit()
    db.refresh(cat)

    logger.info(f"Category {cat_id} updated in space {space_id} by {u.username}")
    return {"id": cat.id, "name": cat.name, "order_idx": cat.order_idx}


@router.delete("/{space_id}/categories/{cat_id}")
async def delete_category(
        space_id: int,
        cat_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Удалить категорию. Комнаты перемещаются в категорию по умолчанию."""
    _require_admin(space_id, u.id, db)

    cat = db.query(SpaceCategory).filter(
        SpaceCategory.id == cat_id,
        SpaceCategory.space_id == space_id,
    ).first()
    if not cat:
        raise HTTPException(404, "Категория не найдена")

    # Нельзя удалить единственную категорию
    total_cats = db.query(SpaceCategory).filter(SpaceCategory.space_id == space_id).count()
    if total_cats <= 1:
        raise HTTPException(400, "Нельзя удалить единственную категорию")

    # Ищем категорию по умолчанию (с наименьшим order_idx, не текущую)
    default_cat = (db.query(SpaceCategory)
                   .filter(SpaceCategory.space_id == space_id, SpaceCategory.id != cat_id)
                   .order_by(SpaceCategory.order_idx)
                   .first())

    # Перемещаем комнаты
    if default_cat:
        db.query(Room).filter(Room.category_id == cat_id).update(
            {"category_id": default_cat.id}, synchronize_session="fetch")

    db.delete(cat)
    db.commit()

    logger.info(f"Category {cat_id} deleted from space {space_id} by {u.username}")
    return {"ok": True, "rooms_moved_to": default_cat.id if default_cat else None}


# ══════════════════════════════════════════════════════════════════════════════
# Комнаты внутри пространства
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{space_id}/rooms", status_code=201)
async def create_space_room(
        space_id: int,
        body: SpaceRoomCreate,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Создать комнату внутри пространства (admin/owner).
    Все участники пространства автоматически добавляются в новую комнату.
    """
    _require_admin(space_id, u.id, db)
    space = _require_space(space_id, db)

    # Проверяем category_id
    category_id = body.category_id
    if category_id:
        cat = db.query(SpaceCategory).filter(
            SpaceCategory.id == category_id,
            SpaceCategory.space_id == space_id,
        ).first()
        if not cat:
            raise HTTPException(404, "Категория не найдена в этом пространстве")
    else:
        # Используем категорию по умолчанию
        default_cat = _get_default_category(space_id, db)
        category_id = default_cat.id if default_cat else None

    # Определяем порядок
    max_order = db.query(Room).filter(
        Room.space_id == space_id,
        Room.category_id == category_id,
    ).count()

    emoji = "🔊" if body.is_voice else ("📢" if body.is_channel else "💬")
    room = Room(
        name         = body.name.strip()[:100],
        description  = body.description.strip()[:500] if body.description else "",
        creator_id   = u.id,
        invite_code  = generative_invite_code(8),
        is_voice     = body.is_voice,
        is_channel   = body.is_channel,
        space_id     = space_id,
        category_id  = category_id,
        order_idx    = max_order,
        avatar_emoji = emoji,
    )
    db.add(room)
    db.flush()

    # Добавляем ВСЕХ участников пространства в новую комнату
    space_members = db.query(SpaceMember).filter(SpaceMember.space_id == space_id).all()
    for sm in space_members:
        room_role = RoomRole.OWNER if sm.user_id == u.id else RoomRole.MEMBER
        db.add(RoomMember(room_id=room.id, user_id=sm.user_id, role=room_role))

    db.commit()
    db.refresh(room)

    from app.chats.rooms import _room_dict
    logger.info(
        f"Room '{room.name}' (id={room.id}) created in space {space_id} "
        f"by {u.username}, {len(space_members)} members added"
    )

    return _room_dict(room)


# ══════════════════════════════════════════════════════════════════════════════
# Аватар пространства
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{space_id}/avatar")
async def upload_space_avatar(
        space_id: int,
        file: UploadFile = File(...),
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Загрузить аватар пространства (admin/owner). Макс. 5 МБ, JPEG/PNG."""
    _require_admin(space_id, u.id, db)
    space = _require_space(space_id, db)

    from PIL import Image
    import io

    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "Макс. 5 МБ")

    try:
        img = Image.open(io.BytesIO(content))
        img = img.convert("RGB")
        img.thumbnail((256, 256))
    except Exception:
        raise HTTPException(400, "Неверный формат изображения")

    os.makedirs("uploads/space_avatars", exist_ok=True)
    filename = f"{_secrets.token_hex(16)}.jpg"
    path = f"uploads/space_avatars/{filename}"
    img.save(path, "JPEG", quality=85)

    space.avatar_url = f"/uploads/space_avatars/{filename}"
    db.commit()

    logger.info(f"Space {space_id} avatar uploaded by {u.username}")
    return {"ok": True, "avatar_url": space.avatar_url}


# ══════════════════════════════════════════════════════════════════════════════
# Тема пространства (per-space theme)
# ══════════════════════════════════════════════════════════════════════════════

import json as _json


class SpaceThemeBody(BaseModel):
    wallpaper: Optional[str] = Field(None, max_length=255)
    accent: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    dark_mode: Optional[bool] = None


_VALID_WALLPAPERS = {"none", "stars", "aurora", "sunset", "ocean-wave", "mesh", "deep-space"}


@router.put("/{space_id}/theme")
async def set_space_theme(
        space_id: int,
        body: SpaceThemeBody,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Установить тему пространства (owner/admin)."""
    _require_admin(space_id, u.id, db)
    space = _require_space(space_id, db)

    d = {}
    if body.wallpaper is not None:
        if body.wallpaper not in _VALID_WALLPAPERS and not body.wallpaper.startswith("http"):
            raise HTTPException(400, f"Недопустимый wallpaper: {body.wallpaper}")
        d["wallpaper"] = body.wallpaper
    if body.accent is not None:
        d["accent"] = body.accent
    if body.dark_mode is not None:
        d["dark_mode"] = body.dark_mode

    space.theme_json = _json.dumps(d, ensure_ascii=False)
    db.commit()

    logger.info(f"Space {space_id} theme set by {u.username}")
    return {"ok": True, "theme": d}


@router.get("/{space_id}/theme")
async def get_space_theme(
        space_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Получить тему пространства."""
    _require_space_member(space_id, u.id, db)
    space = _require_space(space_id, db)
    theme = _json.loads(space.theme_json) if space.theme_json else None
    return {"theme": theme}
