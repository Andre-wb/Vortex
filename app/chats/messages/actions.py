"""
app/chats/chat_actions.py — mark_read, reactions, forward, pin_message handlers.

Extracted from chat.py for maintainability.
"""

from __future__ import annotations

import contextlib
import unicodedata
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.chats.messages._router import epoch_micros as _epoch_micros
from app.chats.messages.envelope_backend import message_sent
from app.models import User
from app.models_rooms import (
    Message,
    MessageReaction,
    Room,
    RoomMember,
    RoomRole,
)
from app.peer.connection_manager import manager
from app.security.sealed_sender import compute_sender_pseudo
from app.transport.blind_mailbox import deposit_envelope


async def _bmp_deposit(room_id: int, payload: dict):
    from app.config import Config

    if not Config.BMP_DELIVERY_ENABLED:
        return
    with contextlib.suppress(Exception):
        import json

        await deposit_envelope(room_id, json.dumps(payload))


# Валидация эмодзи-реакций

# ранее проверялось только len(emoji) <= 10 без charset-фильтра,
# что позволяло протащить HTML/текст (XSS-вектор при рендере реакций).
# Запрещённые символы — потенциальная HTML/атрибутная инъекция.
_REACTION_FORBIDDEN_CHARS = set("<>\"&'/`=")

# Unicode-категории/диапазоны, допустимые внутри grapheme-эмодзи.
_EMOJI_JOINERS = {
    0x200D,  # ZERO WIDTH JOINER
    0xFE0E,
    0xFE0F,  # variation selectors (text/emoji)
}


def _is_emoji_codepoint(ch: str) -> bool:
    """True, если символ — часть эмодзи (пиктограмма, модификатор, флаг и т.п.)."""
    cp = ord(ch)
    if cp in _EMOJI_JOINERS:
        return True
    # Skin-tone modifiers
    if 0x1F3FB <= cp <= 0x1F3FF:
        return True
    # Regional indicators (флаги)
    if 0x1F1E6 <= cp <= 0x1F1FF:
        return True
    # Tag characters (subdivision flags, e.g. флаги Англии/Шотландии)
    if 0xE0020 <= cp <= 0xE007F:
        return True
    # Keycap combining mark
    if cp == 0x20E3:
        return True
    # Unicode So (Symbol, other) — основные эмодзи-пиктограммы
    if unicodedata.category(ch) == "So":
        return True
    # Дополнительные пиктографические/символьные блоки
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x2190 <= cp <= 0x21FF
        or 0x2B00 <= cp <= 0x2BFF
        or cp == 0x1F004
        or cp == 0x1F0CF
    )


def is_valid_reaction_emoji(raw: str | None) -> bool:
    """принимает только эмодзи/grapheme, отвергает HTML и обычный текст."""
    if not raw:
        return False
    emoji = raw.strip()
    if not emoji or len(emoji) > 10:
        return False
    has_pictograph = False
    for ch in emoji:
        if ch in _REACTION_FORBIDDEN_CHARS:
            return False
        if ch in (" ", "\t", "\n", "\r"):
            return False
        if _is_emoji_codepoint(ch):
            has_pictograph = True
            continue
        # Любой другой символ (буквы/цифры/пунктуация/управляющие) — не эмодзи.
        return False
    return has_pictograph


# Прочтение сообщений (read receipts)


async def handle_mark_read(room_id: int, user: User, data: dict, db: Session) -> None:
    """Помечает сообщения прочитанными и уведомляет отправителей."""
    msg_ids = data.get("msg_ids", [])
    if not msg_ids or not isinstance(msg_ids, list):
        return
    # Ограничиваем количество
    msg_ids = [int(i) for i in msg_ids[:200] if isinstance(i, (int, float, str))]
    if not msg_ids:
        return

    # NOTE: last_read_message_id is a known metadata trade-off.
    # Server needs it for unread badge counts. Stored per user+room.
    # Mitigation: read receipts sent to peers via BMP (not WS), so server
    # knows THAT a user read messages but peers learn via encrypted BMP envelope.
    member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user.id,
        )
        .first()
    )
    if member:
        max_id = max(msg_ids)
        if not member.last_read_message_id or max_id > member.last_read_message_id:
            member.last_read_message_id = max_id
            db.commit()

    # Рассылаем уведомление о прочтении
    _read_payload = {"type": "messages_read", "reader_id": user.id, "msg_ids": msg_ids}
    await manager.broadcast_to_room(room_id, _read_payload)


# Реакции на сообщения


async def handle_reaction(room_id: int, user: User, data: dict, db: Session) -> None:
    """Toggle-реакция: добавить если нет, удалить если есть."""
    msg_id = data.get("msg_id")
    emoji = data.get("emoji", "").strip()
    # charset/emoji whitelist (раньше — только len <= 10).
    if not msg_id or not is_valid_reaction_emoji(emoji):
        return

    # Проверяем что сообщение существует в этой комнате
    msg = db.query(Message.id).filter(Message.id == msg_id, Message.room_id == room_id).first()
    if not msg:
        return

    existing = (
        db.query(MessageReaction)
        .filter(
            MessageReaction.message_id == msg_id,
            MessageReaction.user_id == user.id,
            MessageReaction.emoji == emoji,
        )
        .first()
    )

    if existing:
        db.delete(existing)
        db.commit()
        added = False
    else:
        # Лимит: максимум 2 разных реакции от одного пользователя на одно сообщение
        user_reaction_count = (
            db.query(MessageReaction)
            .filter(
                MessageReaction.message_id == msg_id,
                MessageReaction.user_id == user.id,
            )
            .count()
        )
        if user_reaction_count >= 2:
            return  # Молча отклоняем — лимит достигнут

        try:
            db.add(MessageReaction(message_id=msg_id, user_id=user.id, emoji=emoji))
            db.commit()
            added = True
        except IntegrityError:
            db.rollback()
            # Duplicate reaction (race condition) — treat as toggle off
            dup = (
                db.query(MessageReaction)
                .filter(
                    MessageReaction.message_id == msg_id,
                    MessageReaction.user_id == user.id,
                    MessageReaction.emoji == emoji,
                )
                .first()
            )
            if dup:
                db.delete(dup)
                db.commit()
            added = False

    _react_payload = {
        "type": "reaction",
        "msg_id": msg_id,
        "user_id": user.id,
        "username": user.username,
        "display_name": user.display_name or user.username,
        "emoji": emoji,
        "added": added,
        "created_at": datetime.now(timezone.utc).isoformat() + "Z" if added else None,
    }
    await manager.broadcast_to_room(room_id, _react_payload)


# Пересылка сообщений


async def handle_forward(room_id: int, user: User, data: dict, db: Session) -> None:
    """Пересылает сообщение в другую комнату."""
    target_room_id = data.get("target_room_id")
    msg_id = data.get("msg_id")
    if not target_room_id or not msg_id:
        return

    # Проверяем членство в обеих комнатах
    src_member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user.id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not src_member:
        return

    dst_member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == target_room_id,
            RoomMember.user_id == user.id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not dst_member:
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "\u0412\u044b \u043d\u0435 \u0443\u0447\u0430\u0441\u0442\u043d\u0438\u043a \u0446\u0435\u043b\u0435\u0432\u043e\u0439 \u043a\u043e\u043c\u043d\u0430\u0442\u044b",
            },
        )
        return

    # Копируем сообщение
    orig = db.query(Message).filter(Message.id == msg_id, Message.room_id == room_id).first()
    if not orig:
        return

    fwd_from = orig.sender.display_name or orig.sender.username if orig.sender else "?"

    new_msg = Message(
        room_id=target_room_id,
        sender_pseudo=compute_sender_pseudo(target_room_id, user.id),
        msg_type=orig.msg_type,
        content_encrypted=orig.content_encrypted,
        content_hash=orig.content_hash,
        enc_version=orig.enc_version,
        file_name=orig.file_name,
        file_size=orig.file_size,
        forwarded_from=fwd_from,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    await manager.broadcast_to_room(
        target_room_id,
        message_sent(
            msg_id=new_msg.id,
            client_msg_id="",
            ciphertext=orig.content_encrypted.hex() if orig.content_encrypted else "",
            digest_hex=orig.content_hash.hex() if orig.content_hash else "",
            created_at_us=_epoch_micros(new_msg.created_at),
            sender_id=user.id,
            sender_pseudo=new_msg.sender_pseudo,
            sender=user.username,
            display_name=user.display_name,
            avatar_emoji=user.avatar_emoji,
            avatar_url=user.avatar_url,
            is_bot=bool(user.is_bot),
            enc_v=new_msg.enc_version,
            forwarded_from=fwd_from,
        ),
    )

    # Подтверждение отправителю
    await manager.send_to_user(
        room_id,
        user.id,
        {
            "type": "system",
            "message": "\u0421\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0435 \u043f\u0435\u0440\u0435\u0441\u043b\u0430\u043d\u043e",
        },
    )


# Закрепление сообщений


async def handle_pin_message(room_id: int, user: User, data: dict, db: Session) -> None:
    """Закрепляет/открепляет сообщение в комнате."""
    msg_id = data.get("msg_id")

    member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user.id,
        )
        .first()
    )
    if not member or member.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "\u041d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043f\u0440\u0430\u0432 \u0434\u043b\u044f \u0437\u0430\u043a\u0440\u0435\u043f\u043b\u0435\u043d\u0438\u044f",
            },
        )
        return

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        return

    if msg_id:
        # Проверяем существование сообщения
        msg = db.query(Message.id).filter(Message.id == msg_id, Message.room_id == room_id).first()
        if not msg:
            return
        room.pinned_message_id = msg_id
    else:
        room.pinned_message_id = None

    db.commit()

    _pin_payload = {"type": "message_pinned", "msg_id": msg_id}
    await manager.broadcast_to_room(room_id, _pin_payload)
