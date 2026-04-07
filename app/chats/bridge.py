"""
app/chats/bridge.py — Telegram / Matrix import bridge.

Telegram: парсит result.json из официального экспорта (Settings → Export data → JSON)
Matrix:   парсит history.json / messages.json из Element export

Что импортируется:
  - Личные переписки → создаёт DM-комнату с контактом-заглушкой (external_*)
  - Групповые чаты → создаёт group-комнату с именем из экспорта
  - Сообщения → сохраняются как plaintext (байты UTF-8) с пометкой forwarded_from="[TG import]"
  - Контакты из exported contacts.vcf / contact_list.json → добавляются как Contact записи

Ограничения (E2E):
  - Сообщения хранятся в content_encrypted как сырой UTF-8 (не зашифрованы),
    клиент должен расшифровать при показе или показывать как legacy plaintext.
  - Медиафайлы не импортируются (только текст).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models.contact import Contact
from app.models_rooms import Message, MessageType, Room, RoomMember, RoomRole
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/bridge", tags=["bridge"])

_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_or_create_external_user(username: str, display_name: str, db: Session) -> User:
    """Находит или создаёт пользователя-заглушку для внешних контактов."""
    slug = f"ext_{username[:40]}"
    user = db.query(User).filter(User.username == slug).first()
    if not user:
        import secrets
        user = User(
            username=slug,
            display_name=display_name[:100] if display_name else username,
            phone=f"+0{secrets.token_hex(6)}",  # dummy phone
            password_hash="!external",           # не может войти
            avatar_emoji="👤",
            is_active=True,
        )
        db.add(user)
        db.flush()
    return user


def _get_or_create_dm_room(user_a: User, user_b: User, db: Session) -> Room:
    """Находит или создаёт DM-комнату между двумя пользователями."""
    # Ищем существующую DM
    existing = (
        db.query(Room)
        .filter(Room.is_dm == True)
        .join(RoomMember, RoomMember.room_id == Room.id)
        .filter(RoomMember.user_id == user_a.id)
        .all()
    )
    for room in existing:
        members = db.query(RoomMember).filter(RoomMember.room_id == room.id).all()
        ids = {m.user_id for m in members}
        if ids == {user_a.id, user_b.id}:
            return room

    room = Room(
        name=f"dm_{user_a.id}_{user_b.id}",
        is_dm=True,
        is_private=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(room)
    db.flush()
    for u in (user_a, user_b):
        db.add(RoomMember(room_id=room.id, user_id=u.id, role=RoomRole.MEMBER))
    return room


def _get_or_create_group_room(name: str, owner: User, db: Session) -> Room:
    """Находит или создаёт групповую комнату по имени (для импорта)."""
    slug = f"[import] {name}"[:100]
    room = db.query(Room).filter(Room.name == slug).first()
    if not room:
        room = Room(
            name=slug,
            is_private=False,
            is_dm=False,
            created_at=datetime.now(timezone.utc),
        )
        db.add(room)
        db.flush()
        db.add(RoomMember(room_id=room.id, user_id=owner.id, role=RoomRole.OWNER))
    return room


def _save_message(room: Room, sender: User, text: str, ts: datetime, source: str, db: Session) -> None:
    """Сохраняет текстовое сообщение из импорта."""
    if not text or not text.strip():
        return
    content = text.encode("utf-8", errors="replace")
    db.add(Message(
        room_id=room.id,
        sender_id=sender.id,
        msg_type=MessageType.TEXT,
        content_encrypted=content,
        forwarded_from=f"[{source}]",
        created_at=ts,
    ))


def _parse_tg_timestamp(ts: Any) -> datetime:
    """Парсит Telegram timestamp (строка ISO или int)."""
    if isinstance(ts, int):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Telegram import
# ─────────────────────────────────────────────────────────────────────────────

def _import_telegram(data: dict, user: User, db: Session) -> dict:
    """
    Парсит result.json от Telegram export.
    Структура: {"chats": {"list": [{"type": "...", "name": "...", "messages": [...]}]}}
    """
    chats = data.get("chats", {}).get("list", [])
    if not chats:
        # Попробуем плоский формат (один чат)
        if "messages" in data:
            chats = [data]

    stats = {"chats": 0, "messages": 0, "contacts": 0}

    for chat in chats:
        chat_type = chat.get("type", "")
        chat_name = chat.get("name", "Unknown")
        messages  = chat.get("messages", [])

        if chat_type in ("personal_chat", "saved_messages"):
            # DM или избранное
            if chat_type == "saved_messages":
                other = user
            else:
                ext = _get_or_create_external_user(
                    username=chat_name.lower().replace(" ", "_"),
                    display_name=chat_name,
                    db=db,
                )
                other = ext
            room = _get_or_create_dm_room(user, other, db)
        elif chat_type in ("private_group", "private_supergroup", "public_supergroup", "public_channel", "private_channel"):
            room = _get_or_create_group_room(chat_name, user, db)
        else:
            room = _get_or_create_group_room(chat_name or "Imported", user, db)

        stats["chats"] += 1

        for msg in messages:
            # text может быть строкой или списком (bold/italic entities)
            raw_text = msg.get("text", "")
            if isinstance(raw_text, list):
                parts = []
                for part in raw_text:
                    if isinstance(part, str):
                        parts.append(part)
                    elif isinstance(part, dict):
                        parts.append(part.get("text", ""))
                text = "".join(parts)
            else:
                text = str(raw_text)

            if not text.strip():
                continue

            ts = _parse_tg_timestamp(msg.get("date", ""))
            from_name = msg.get("from", user.display_name or user.username)
            from_id   = msg.get("from_id", "")

            # Определяем отправителя
            if str(from_id) == str(user.id) or not from_id:
                sender = user
            else:
                sender = _get_or_create_external_user(
                    username=str(from_id).lower().replace(" ", "_")[:40],
                    display_name=from_name,
                    db=db,
                )

            _save_message(room, sender, text, ts, "TG", db)
            stats["messages"] += 1

        if stats["messages"] % 500 == 0 and stats["messages"] > 0:
            db.flush()

    db.commit()
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Matrix import
# ─────────────────────────────────────────────────────────────────────────────

def _import_matrix(data: dict | list, user: User, db: Session) -> dict:
    """
    Парсит Matrix export (Element/FluffyChat).
    Форматы:
      - {"rooms": [{"name": "...", "events": [...]}]}
      - [{"type": "m.room.message", "sender": "@alice:server", "content": {...}, "origin_server_ts": ...}]
    """
    stats = {"chats": 0, "messages": 0, "contacts": 0}

    if isinstance(data, list):
        # Плоский список event'ов — один чат
        rooms_data = [{"name": "Matrix Import", "events": data}]
    else:
        rooms_data = data.get("rooms", [])
        if not rooms_data and "events" in data:
            rooms_data = [{"name": data.get("name", "Matrix Import"), "events": data["events"]}]

    for room_data in rooms_data:
        room_name = room_data.get("name") or room_data.get("room_id", "Matrix Room")
        events    = room_data.get("events", room_data.get("messages", []))

        room = _get_or_create_group_room(room_name, user, db)
        stats["chats"] += 1

        for event in events:
            if event.get("type") != "m.room.message":
                continue
            content = event.get("content", {})
            if content.get("msgtype") not in ("m.text", "m.notice", "m.emote"):
                continue

            text = content.get("body", "")
            if not text.strip():
                continue

            ts_ms = event.get("origin_server_ts", 0)
            ts = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc) if ts_ms else datetime.now(timezone.utc)

            sender_mxid = event.get("sender", "")
            localpart = sender_mxid.split(":")[0].lstrip("@")[:40] or "matrix_user"
            sender = _get_or_create_external_user(
                username=localpart,
                display_name=localpart,
                db=db,
            ) if sender_mxid != f"@{user.username}:{localpart}" else user

            _save_message(room, sender, text, ts, "Matrix", db)
            stats["messages"] += 1

        if stats["messages"] % 500 == 0 and stats["messages"] > 0:
            db.flush()

    db.commit()
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/telegram")
async def import_telegram(
    file: UploadFile = File(...),
    u: User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Импорт из Telegram.
    Загрузите result.json из Telegram → Настройки → Экспорт данных (формат JSON).
    """
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "Ожидается файл result.json от Telegram")

    raw = await file.read(_MAX_FILE_SIZE + 1)
    if len(raw) > _MAX_FILE_SIZE:
        raise HTTPException(413, "Файл слишком большой (максимум 50 МБ)")

    try:
        data = json.loads(raw)
    except Exception:
        raise HTTPException(400, "Невалидный JSON")

    try:
        stats = _import_telegram(data, u, db)
    except Exception as e:
        logger.exception("Telegram import error")
        raise HTTPException(500, f"Ошибка импорта: {e}")

    return {
        "ok": True,
        "imported_chats":    stats["chats"],
        "imported_messages": stats["messages"],
        "note": "Сообщения импортированы как plaintext и помечены [TG]. Медиафайлы не импортируются.",
    }


@router.post("/matrix")
async def import_matrix(
    file: UploadFile = File(...),
    u: User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Импорт из Matrix / Element.
    Загрузите JSON-экспорт из Element → Room settings → Export chat history.
    """
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "Ожидается .json файл экспорта Matrix/Element")

    raw = await file.read(_MAX_FILE_SIZE + 1)
    if len(raw) > _MAX_FILE_SIZE:
        raise HTTPException(413, "Файл слишком большой (максимум 50 МБ)")

    try:
        data = json.loads(raw)
    except Exception:
        raise HTTPException(400, "Невалидный JSON")

    try:
        stats = _import_matrix(data, u, db)
    except Exception as e:
        logger.exception("Matrix import error")
        raise HTTPException(500, f"Ошибка импорта: {e}")

    return {
        "ok": True,
        "imported_chats":    stats["chats"],
        "imported_messages": stats["messages"],
        "note": "Сообщения импортированы как plaintext и помечены [Matrix]. Зашифрованные события пропущены.",
    }
