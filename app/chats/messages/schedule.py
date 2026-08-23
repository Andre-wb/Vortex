"""
app/chats/chat_schedule.py — Scheduled messages, timed (self-destructing) messages,
delivery loop, and expired-message cleanup.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.chats.messages._router import epoch_micros, utc_iso
from app.chats.messages.envelope_backend import message_ack, message_read, message_sent
from app.models import User
from app.models_rooms import Message, MessageType
from app.peer.connection_manager import manager
from app.security.sealed_sender import compute_sender_pseudo

logger = logging.getLogger(__name__)


def _read_envelope(data: dict, action: str):
    """Разбор входящего кадра Rust-ом: границы, hex, версия, метка, упоминания."""
    return message_read(json.dumps(data), action, epoch_micros(datetime.now(timezone.utc)))


async def handle_timed_message(room_id: int, user: User, data: dict, db: Session) -> None:
    """Отправляет сообщение с таймером самоуничтожения."""
    if not manager.check_rate_limit(room_id, user.id):
        return

    parsed = _read_envelope(data, "message")
    if parsed.refusal:
        await manager.send_to_user(room_id, user.id, parsed.refusal.frame())
        return

    ttl_seconds = data.get("ttl_seconds", 60)
    expires = datetime.now(timezone.utc) + timedelta(seconds=min(int(ttl_seconds), 86400))

    msg = Message(
        room_id=room_id,
        sender_pseudo=compute_sender_pseudo(room_id, user.id),
        msg_type=MessageType.TEXT,
        content_encrypted=bytes(parsed.content),
        content_hash=bytes(parsed.digest),
        enc_version=parsed.enc_v,
        expires_at=expires,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    await manager.send_to_user(
        room_id,
        user.id,
        message_ack(parsed.client_msg_id, msg.id, epoch_micros(msg.created_at)),
    )

    await manager.broadcast_to_room(
        room_id,
        message_sent(
            msg_id=msg.id,
            client_msg_id=parsed.client_msg_id,
            ciphertext=parsed.ciphertext,
            digest_hex=parsed.digest_hex,
            created_at_us=epoch_micros(msg.created_at),
            sender_id=user.id,
            sender_pseudo=msg.sender_pseudo,
            sender=user.username,
            display_name=user.display_name,
            avatar_emoji=user.avatar_emoji,
            avatar_url=user.avatar_url,
            is_bot=bool(user.is_bot),
            enc_v=parsed.enc_v,
            expires_at_us=epoch_micros(expires),
        ),
    )


async def handle_schedule_message(room_id: int, user: User, data: dict, db: Session) -> None:
    """Сохраняет сообщение для отложенной отправки."""
    if user.global_muted_until and user.global_muted_until > datetime.now(timezone.utc):
        remaining = user.global_muted_until - datetime.now(timezone.utc)
        days = remaining.days
        hours = remaining.seconds // 3600
        if days > 0:
            time_str = f"{days}d {hours}h"
        elif hours > 0:
            time_str = f"{hours}h {remaining.seconds % 3600 // 60}m"
        else:
            time_str = f"{remaining.seconds // 60}m"
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": f"You are muted on the platform. Remaining: {time_str}",
                "code": "global_muted",
            },
        )
        return

    parsed = _read_envelope(data, "message")
    if parsed.refusal:
        await manager.send_to_user(room_id, user.id, parsed.refusal.frame())
        return

    scheduled_at_str = data.get("scheduled_at", "")
    client_msg_id = parsed.client_msg_id

    if not scheduled_at_str:
        return

    try:
        scheduled_at = datetime.fromisoformat(scheduled_at_str.replace("Z", "+00:00"))
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        await manager.send_to_user(room_id, user.id, {"type": "error", "message": "Invalid date"})
        return

    if scheduled_at <= datetime.now(timezone.utc):
        await manager.send_to_user(room_id, user.id, {"type": "error", "message": "Date must be in the future"})
        return

    msg = Message(
        room_id=room_id,
        sender_pseudo=compute_sender_pseudo(room_id, user.id),
        msg_type=MessageType.TEXT,
        content_encrypted=bytes(parsed.content),
        content_hash=bytes(parsed.digest),
        enc_version=parsed.enc_v,
        reply_to_id=parsed.reply_to_id,
        scheduled_at=scheduled_at,
        is_scheduled=True,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    await manager.send_to_user(
        room_id,
        user.id,
        {
            "type": "ack",
            "msg_id": client_msg_id,
            "server_id": msg.id,
            "scheduled": True,
            "scheduled_at": utc_iso(scheduled_at),
        },
    )
    await manager.send_to_user(
        room_id,
        user.id,
        {
            "type": "system",
            "message": f"Message scheduled for {scheduled_at.strftime('%Y-%m-%d %H:%M')}",
        },
    )


async def deliver_scheduled_messages(db: Session) -> int:
    """Доставляет запланированные сообщения, у которых наступило время."""
    now = datetime.now(timezone.utc)
    scheduled = (
        db.query(Message)
        .filter(
            Message.is_scheduled.is_(True),
            Message.scheduled_at.is_not(None),
            Message.scheduled_at <= now,
        )
        .all()
    )

    delivered = 0
    for msg in scheduled:
        msg.is_scheduled = False
        msg.created_at = now
        db.commit()
        db.refresh(msg)

        ciphertext_hex = msg.content_encrypted.hex() if msg.content_encrypted else ""

        await manager.broadcast_to_room(
            msg.room_id,
            message_sent(
                msg_id=msg.id,
                client_msg_id="",
                ciphertext=ciphertext_hex,
                digest_hex=msg.content_hash.hex() if msg.content_hash else "",
                created_at_us=epoch_micros(msg.created_at),
                sender_id=msg.sender_id,
                sender_pseudo=msg.sender_pseudo,
                sender=msg.sender.username if msg.sender else "—",
                display_name=msg.sender.display_name if msg.sender else "—",
                avatar_emoji=msg.sender.avatar_emoji if msg.sender else None,
                avatar_url=msg.sender.avatar_url if msg.sender else None,
                enc_v=msg.enc_version,
                reply_to_id=msg.reply_to_id,
            ),
        )
        delivered += 1

    if delivered:
        logger.info("Delivered %d scheduled messages", delivered)
    return delivered


async def cleanup_expired_messages(db: Session) -> int:
    """Удаляет просроченные сообщения. Возвращает количество удалённых."""
    expired = (
        db.query(Message)
        .filter(
            Message.expires_at.is_not(None),
            Message.expires_at < datetime.now(timezone.utc),
        )
        .all()
    )

    deleted = 0
    rooms_to_notify: dict[int, list[int]] = {}
    for msg in expired:
        rooms_to_notify.setdefault(msg.room_id, []).append(msg.id)
        db.delete(msg)
        deleted += 1

    if deleted:
        db.commit()
        for rid, msg_ids in rooms_to_notify.items():
            for mid in msg_ids:
                await manager.broadcast_to_room(rid, {"type": "message_deleted", "msg_id": mid})
        logger.debug("Cleaned up %d expired messages", deleted)

    # Deliver any scheduled messages that are now due
    await deliver_scheduled_messages(db)

    return deleted
