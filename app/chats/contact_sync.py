"""
app/chats/contact_sync.py — Синхронизация контактов с устройства.

Клиент отправляет SHA-256 хеши номеров телефонов (приватность),
сервер сравнивает с нормализованными хешами телефонов пользователей в БД.
Найденные совпадения возвращаются клиенту для добавления в контакты.

Эндпоинты:
  - POST /api/contacts/sync          — отправить хеши, получить совпадения
  - POST /api/contacts/sync/add-all  — добавить все найденные совпадения в контакты
"""
from __future__ import annotations

import hashlib
import logging
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models.contact import Contact
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/contacts/sync", tags=["contacts"])

_PHONE_NORM_RE = re.compile(r"[^\d+]")


def _normalize_phone(phone: str) -> str:
    """Убираем пробелы, скобки, дефисы — оставляем только цифры и +."""
    return _PHONE_NORM_RE.sub("", phone.strip())


def _hash_phone(phone: str) -> str:
    """SHA-256 хеш нормализованного номера (lowercase hex)."""
    return hashlib.sha256(_normalize_phone(phone).encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic схемы
# ══════════════════════════════════════════════════════════════════════════════

class SyncRequest(BaseModel):
    """Клиент отправляет хеши номеров телефонов из адресной книги."""
    phone_hashes: list[str] = Field(
        ..., min_length=1, max_length=5000,
        description="SHA-256 hex хеши нормализованных номеров телефонов",
    )


class AddAllRequest(BaseModel):
    """Добавить всех найденных пользователей в контакты."""
    user_ids: list[int] = Field(
        ..., min_length=1, max_length=5000,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Эндпоинты
# ══════════════════════════════════════════════════════════════════════════════

@router.post("")
async def sync_contacts(
    body: SyncRequest,
    u:    User    = Depends(get_current_user),
    db:   Session = Depends(get_db),
):
    """
    Принимает SHA-256 хеши телефонов из адресной книги устройства.
    Сравнивает с хешами номеров зарегистрированных пользователей.
    Возвращает совпадения (без раскрытия номеров).
    """
    incoming_hashes = set(h.lower() for h in body.phone_hashes if len(h) == 64)
    if not incoming_hashes:
        return {"matches": [], "total_checked": 0}

    # Получаем всех пользователей с номерами телефонов (кроме текущего)
    users_with_phone = (
        db.query(User)
        .filter(User.phone.isnot(None), User.phone != "", User.is_active == True, User.id != u.id)
        .all()
    )

    # Уже добавленные контакты — не показываем повторно
    existing_contact_ids = set(
        r[0] for r in
        db.query(Contact.contact_id).filter(Contact.owner_id == u.id).all()
    )

    matches = []
    for user in users_with_phone:
        user_phone_hash = _hash_phone(user.phone)
        if user_phone_hash in incoming_hashes and user.id not in existing_contact_ids:
            matches.append({
                "user_id":      user.id,
                "username":     user.username,
                "display_name": user.display_name or user.username,
                "avatar_emoji": user.avatar_emoji,
                "avatar_url":   user.avatar_url,
                "presence":     user.presence or "online",
            })

    logger.info(
        "contact_sync user=%s checked=%d matched=%d",
        u.id, len(incoming_hashes), len(matches),
    )

    return {
        "matches":       matches,
        "total_checked": len(incoming_hashes),
        "already_added": len(existing_contact_ids),
    }


@router.post("/add-all", status_code=201)
async def add_all_matched(
    body: AddAllRequest,
    u:    User    = Depends(get_current_user),
    db:   Session = Depends(get_db),
):
    """Массовое добавление найденных пользователей в контакты."""
    existing_contact_ids = set(
        r[0] for r in
        db.query(Contact.contact_id).filter(Contact.owner_id == u.id).all()
    )

    added = 0
    for uid in body.user_ids:
        if uid == u.id or uid in existing_contact_ids:
            continue
        # Проверяем что пользователь существует
        target = db.query(User).filter(User.id == uid, User.is_active == True).first()
        if not target:
            continue
        contact = Contact(owner_id=u.id, contact_id=uid)
        db.add(contact)
        existing_contact_ids.add(uid)
        added += 1

    if added:
        db.commit()

    return {"ok": True, "added": added}
