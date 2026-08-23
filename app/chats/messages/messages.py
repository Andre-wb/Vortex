"""
app/chats/chat_messages.py — E2E message handlers: send, thread reply, edit, delete.

Extracted from chat.py for maintainability.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func as sa_func
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from app.chats.messages._router import (
    epoch_micros as _epoch_micros,
)
from app.chats.messages._router import (
    from_epoch_micros as _from_epoch_micros,
)
from app.chats.messages._router import (
    utc_iso as _utc_iso,
)
from app.chats.messages.envelope_backend import (
    MESSAGE_LIMITS,
    message_ack,
    message_ack_duplicate,
    message_deleted,
    message_edited,
    message_read,
    message_sent,
    message_thread_sent,
    message_thread_update,
)
from app.chats.messages.flood import check_flood as _check_flood
from app.chats.messages.push import send_web_push as _send_web_push
from app.federation.replication import maybe_replicate as _maybe_replicate
from app.models import User
from app.models_rooms import (
    Message,
    MessageType,
    Room,
    RoomMember,
    RoomRole,
)
from app.peer.connection_manager import manager
from app.security.sealed_sender import compute_sender_pseudo, resolve_pseudo, verify_sender_pseudo
from app.transport.blind_mailbox import deposit_envelope

logger = logging.getLogger(__name__)

MAX_CIPHERTEXT_HEX_LEN = MESSAGE_LIMITS["max_ciphertext_hex"]


def _read_envelope(data: dict, action: str):
    """Разбор входящего кадра Rust-ом: границы, hex, версия, метка, упоминания."""
    now = _epoch_micros(datetime.now(timezone.utc))
    return message_read(json.dumps(data), action, now)


async def _bmp_deposit(room_id: int, payload: dict):
    """Deposit message payload into BMP mailbox for the room (hybrid mode)."""
    from app.config import Config

    if not Config.BMP_DELIVERY_ENABLED:
        return
    try:
        await deposit_envelope(room_id, json.dumps(payload))
    except Exception as e:
        logger.debug("[BMP] Deposit failed for room %d: %s", room_id, e)


# E2E message


async def handle_e2e_message(room_id: int, user: User, data: dict, db: Session) -> None:
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

    if not manager.check_rate_limit(room_id, user.id):
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "Too many messages. Please wait.",
                "code": "rate_limited",
            },
        )
        return

    room_obj = db.query(Room).filter(Room.id == room_id).first()
    _is_dm = room_obj and room_obj.is_dm
    _antispam = room_obj.antispam_enabled if (room_obj and room_obj.antispam_enabled is not None) else True

    if _antispam and not _is_dm:
        from app.bots.antispam_bot import (
            check_caps_spam,
            check_link_spam,
            check_repeat_spam,
            get_antispam_bot_user_id,
            get_antispam_config,
        )

        # Skip antispam for the bot itself
        _bot_uid = get_antispam_bot_user_id()
        _is_antispam_bot = _bot_uid and user.id == _bot_uid

        if not _is_antispam_bot:
            member_flood = (
                db.query(RoomMember)
                .filter(
                    RoomMember.room_id == room_id,
                    RoomMember.user_id == user.id,
                )
                .first()
            )
            if member_flood and member_flood.muted_until and member_flood.muted_until > datetime.now(timezone.utc):
                remaining = int((member_flood.muted_until - datetime.now(timezone.utc)).total_seconds())
                await manager.send_to_user(
                    room_id,
                    user.id,
                    {
                        "type": "error",
                        "message": f"You are muted. Remaining: {remaining} sec.",
                        "code": "flood_muted",
                    },
                )
                return

            # Use configurable threshold from room settings
            _cfg = get_antispam_config(room_obj) if room_obj else {}
            _threshold = _cfg.get("threshold", 0)
            if await _check_flood(room_id, user, db, threshold_override=_threshold):
                return

            _plaintext = data.get("plaintext_command", "") or data.get("plaintext_hint", "")
            if _plaintext and isinstance(_plaintext, str):
                _member_role = member_flood.role if member_flood else RoomRole.MEMBER

                if _cfg.get("block_repeats", True) and await check_repeat_spam(room_id, user, _plaintext, db):
                    return

                if _cfg.get("block_links", True) and await check_link_spam(room_id, user, _plaintext, _member_role, db):
                    return

                if await check_caps_spam(room_id, user, _plaintext, db):
                    return

    if room_obj and room_obj.is_channel:
        member = (
            db.query(RoomMember)
            .filter(
                RoomMember.room_id == room_id,
                RoomMember.user_id == user.id,
            )
            .first()
        )
        if not member or member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
            await manager.send_to_user(
                room_id, user.id, {"type": "error", "message": "Only admins can post in channels"}
            )
            return

    if room_obj and room_obj.slow_mode_seconds and room_obj.slow_mode_seconds > 0 and not room_obj.is_dm:
        member_sm = (
            db.query(RoomMember)
            .filter(
                RoomMember.room_id == room_id,
                RoomMember.user_id == user.id,
            )
            .first()
        )
        if member_sm and member_sm.role == RoomRole.MEMBER:
            _user_pseudo = compute_sender_pseudo(room_id, user.id)
            last_msg = (
                db.query(Message)
                .filter(
                    Message.room_id == room_id,
                    Message.sender_pseudo == _user_pseudo,
                )
                .order_by(Message.created_at.desc())
                .first()
            )
            if last_msg:
                elapsed = (datetime.now(timezone.utc) - last_msg.created_at).total_seconds()
                if elapsed < room_obj.slow_mode_seconds:
                    remaining = int(room_obj.slow_mode_seconds - elapsed)
                    await manager.send_to_user(
                        room_id,
                        user.id,
                        {
                            "type": "error",
                            "message": f"Please wait {remaining} sec (slow mode)",
                            "code": "slow_mode",
                        },
                    )
                    return

    parsed = _read_envelope(data, "message")
    if parsed.refusal:
        await manager.send_to_user(room_id, user.id, parsed.refusal.frame())
        return

    ciphertext_hex = parsed.ciphertext
    client_msg_id = parsed.client_msg_id

    if client_msg_id:
        dedup_key = f"msg:{room_id}:{client_msg_id}"
        if await manager.is_duplicate_message(dedup_key):
            # Повторная отправка — шлём ACK без сохранения
            await manager.send_to_user(room_id, user.id, message_ack_duplicate(client_msg_id))
            return

    ciphertext_bytes = bytes(parsed.content)
    content_hash = bytes(parsed.digest)

    reply_to_id = parsed.reply_to_id
    if reply_to_id:
        reply_exists = (
            db.query(Message.id)
            .filter(
                Message.id == reply_to_id,
                Message.room_id == room_id,
            )
            .first()
        )
        if not reply_exists:
            reply_to_id = None

    mentioned_usernames: list[str] = list(parsed.mentions)

    auto_expire = None
    if room_obj and room_obj.auto_delete_seconds and room_obj.auto_delete_seconds > 0:
        auto_expire = datetime.now(timezone.utc) + timedelta(seconds=room_obj.auto_delete_seconds)

    client_created_at = None if parsed.client_ts_us is None else _from_epoch_micros(parsed.client_ts_us)
    enc_v = parsed.enc_v

    msg = Message(
        room_id=room_id,
        sender_pseudo=compute_sender_pseudo(room_id, user.id),
        msg_type=MessageType.TEXT,
        content_encrypted=ciphertext_bytes,
        content_hash=content_hash,
        enc_version=enc_v,
        reply_to_id=reply_to_id,
        expires_at=auto_expire,
    )
    if client_created_at:
        msg.created_at = client_created_at
    db.add(msg)
    try:
        # Update room's updated_at for sorting
        _room_obj = db.query(Room).filter(Room.id == room_id).first()
        if _room_obj:
            _room_obj.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(msg)
    except Exception as e:
        db.rollback()
        logger.error("Failed to save message in room %s: %s", room_id, e)
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "Failed to save message",
            },
        )
        return

    await manager.send_to_user(
        room_id,
        user.id,
        message_ack(client_msg_id, msg.id, _epoch_micros(msg.created_at)),
    )

    # Fetch sender's tag in this room
    _sender_member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user.id,
        )
        .first()
    )

    payload = message_sent(
        msg_id=msg.id,
        client_msg_id=client_msg_id,
        ciphertext=ciphertext_hex,
        digest_hex=parsed.digest_hex,
        created_at_us=_epoch_micros(msg.created_at),
        sender_id=user.id,
        sender_pseudo=msg.sender_pseudo,
        sender=user.username,
        display_name=user.display_name,
        avatar_emoji=user.avatar_emoji,
        avatar_url=user.avatar_url,
        is_bot=bool(user.is_bot),
        tag=getattr(_sender_member, "tag", None) if _sender_member else None,
        tag_color=getattr(_sender_member, "tag_color", None) if _sender_member else None,
        reply_color=user.reply_color,
        reply_icon=user.reply_icon,
        enc_v=enc_v,
        reply_to_id=reply_to_id,
        reply_quote=parsed.reply_quote,
        forwarded_from=msg.forwarded_from,
        expires_at_us=None if msg.expires_at is None else _epoch_micros(msg.expires_at),
    )
    _room_member_ids = [
        rm.user_id
        for rm in db.query(RoomMember.user_id)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.is_banned.is_(False),
        )
        .all()
    ]

    # WS broadcast removed — server no longer reveals who receives what.
    # Messages are deposited into anonymous BMP mailboxes.
    # Pending queue still works for offline users (fallback via WS on reconnect).
    await _bmp_deposit(room_id, payload)
    # Keep pending queue for offline delivery (BMP TTL = 2h, pending = 7d)
    await manager.enqueue_pending(room_id, payload, member_ids=_room_member_ids)

    # No-op unless `room.replication_mode == 'federated'`. Metadata leak is
    # intentional and surfaced to users via the warning banner; content
    # stays E2E-encrypted.
    if _room_obj is not None:
        try:
            _sender_ts = int(msg.created_at.timestamp()) if msg.created_at else 0
        except Exception:
            _sender_ts = 0
        await _maybe_replicate(_room_obj, payload, _sender_ts)

    # Client may include plaintext_command when text starts with '/'
    # (server can't see E2E-encrypted text, so client provides the hint)
    _bot_cmd_text = data.get("plaintext_command", "")
    if _bot_cmd_text and isinstance(_bot_cmd_text, str) and _bot_cmd_text.startswith("/"):
        # Handle built-in antispam bot commands
        _cmd_lower = _bot_cmd_text.strip().split()[0].lower()
        if _cmd_lower in ("/antispam_status", "/antispam_help"):
            try:
                from app.bots.antispam_bot import handle_antispam_command

                await handle_antispam_command(room_id, _cmd_lower, db)
            except Exception as e:
                logger.warning(f"Antispam command error: {e}")

        try:
            from app.bots.bot_api import notify_bots_in_room

            await notify_bots_in_room(
                room_id=room_id,
                sender_id=user.id,
                text=_bot_cmd_text,
                msg_id=msg.id,
                sender_username=user.username,
                sender_display_name=user.display_name or user.username,
                db=db,
            )
        except Exception as e:
            logger.warning(f"Bot notification error: {e}")

    room_obj = db.query(Room).filter(Room.id == room_id).first()
    is_dm = room_obj.is_dm if room_obj else False

    # Определяем кому был reply (для отображения @ mention)
    reply_to_user_id = None
    if reply_to_id:
        reply_msg = db.query(Message).filter(Message.id == reply_to_id).first()
        if reply_msg:
            if reply_msg.sender_id:
                reply_to_user_id = reply_msg.sender_id
            elif reply_msg.sender_pseudo:
                _rm_ids = [
                    rm.user_id
                    for rm in db.query(RoomMember)
                    .filter(RoomMember.room_id == room_id)
                    .with_entities(RoomMember.user_id)
                    .all()
                ]
                reply_to_user_id = resolve_pseudo(room_id, _rm_ids, reply_msg.sender_pseudo, caller="reply_notify")

    # Build set of mentioned user ids (from @username list sent by client)
    _mentioned_user_ids: set[int] = set()
    if mentioned_usernames:
        mentioned_users = db.query(User.id).filter(sa_func.lower(User.username).in_(mentioned_usernames)).all()
        _mentioned_user_ids = {u.id for u in mentioned_users}

    room_members_full = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.is_banned.is_(False),
        )
        .all()
    )
    # BMP mode: notifications go through BMP deposit (already done above).
    # Anonymous push proxy handles wake signals (Phase 6).
    # No targeted notify_user — zero metadata leakage.
    # Web Push via anonymous push proxy category signal:
    from app.config import Config

    if Config.BMP_DELIVERY_ENABLED:
        pass  # BMP deposit already sends wake signal via _emit_wake_signal
    else:
        # Legacy fallback for non-BMP mode
        online_in_room = set(manager._rooms.get(room_id, {}).keys())
        for rm in room_members_full:
            member_id = rm.user_id
            if member_id not in online_in_room and member_id != user.id:
                if rm.is_muted:
                    continue
                is_mention = (reply_to_user_id == member_id) or (member_id in _mentioned_user_ids)
                delivered = await manager.notify_user(
                    member_id,
                    {
                        "type": "notification",
                        "room_id": room_id,
                        "room_name": room_obj.name if room_obj else "",
                        "is_dm": is_dm,
                        "sender_pseudo": msg.sender_pseudo,
                        "sender_username": user.username,
                        "sender_display_name": user.display_name or user.username,
                        "sender_avatar": user.avatar_emoji,
                        "sender_avatar_url": user.avatar_url,
                        "is_mention": is_mention,
                        "created_at": _utc_iso(msg.created_at),
                    },
                )

                if not delivered:
                    await _send_web_push(
                        member_id,
                        user.display_name or user.username,
                        room_id,
                        is_dm,
                        db,
                    )


# Thread reply


async def handle_thread_reply(room_id: int, user: User, data: dict, db: Session) -> None:
    """Обработка ответа в треде: создаёт сообщение с thread_id и обновляет thread_count."""
    parsed = _read_envelope(data, "thread_reply")
    if parsed.refusal:
        await manager.send_to_user(room_id, user.id, parsed.refusal.frame())
        return

    thread_id = parsed.thread_id
    ciphertext_hex = parsed.ciphertext
    client_msg_id = parsed.client_msg_id

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

    # Rate limiting
    if not manager.check_rate_limit(room_id, user.id):
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "Too many messages. Please wait.",
                "code": "rate_limited",
            },
        )
        return

    # Flood auto-mute check (skipped for DMs and if antispam disabled)
    _room_for_flood = db.query(Room).filter(Room.id == room_id).first()
    _is_dm2 = _room_for_flood and _room_for_flood.is_dm
    _antispam2 = (
        _room_for_flood.antispam_enabled if (_room_for_flood and _room_for_flood.antispam_enabled is not None) else True
    )
    if _antispam2 and not _is_dm2:
        from app.bots.antispam_bot import get_antispam_bot_user_id as _get_bot_uid2
        from app.bots.antispam_bot import get_antispam_config as _get_as_cfg2

        _bot_uid2 = _get_bot_uid2()
        if not (_bot_uid2 and user.id == _bot_uid2):
            member_flood = (
                db.query(RoomMember)
                .filter(
                    RoomMember.room_id == room_id,
                    RoomMember.user_id == user.id,
                )
                .first()
            )
            if member_flood and member_flood.muted_until and member_flood.muted_until > datetime.now(timezone.utc):
                remaining = int((member_flood.muted_until - datetime.now(timezone.utc)).total_seconds())
                await manager.send_to_user(
                    room_id,
                    user.id,
                    {
                        "type": "error",
                        "message": f"You are muted. Remaining: {remaining} sec.",
                        "code": "flood_muted",
                    },
                )
                return
            _cfg2 = _get_as_cfg2(_room_for_flood) if _room_for_flood else {}
            _thr2 = _cfg2.get("threshold", 0)
            if await _check_flood(room_id, user, db, threshold_override=_thr2):
                return

    # Проверяем что корневое сообщение существует в этой комнате
    root_msg = (
        db.query(Message)
        .filter(
            Message.id == thread_id,
            Message.room_id == room_id,
        )
        .first()
    )
    if not root_msg:
        await manager.send_to_user(room_id, user.id, {"type": "error", "message": "Thread root message not found"})
        return

    # Дедупликация
    if client_msg_id:
        dedup_key = f"msg:{room_id}:{client_msg_id}"
        if await manager.is_duplicate_message(dedup_key):
            await manager.send_to_user(room_id, user.id, message_ack_duplicate(client_msg_id))
            return

    ciphertext_bytes = bytes(parsed.content)
    content_hash = bytes(parsed.digest)

    reply_to_id = parsed.reply_to_id
    enc_v = parsed.enc_v

    msg = Message(
        room_id=room_id,
        sender_pseudo=compute_sender_pseudo(room_id, user.id),
        msg_type=MessageType.TEXT,
        content_encrypted=ciphertext_bytes,
        content_hash=content_hash,
        enc_version=enc_v,
        reply_to_id=reply_to_id,
        thread_id=thread_id,
    )
    db.add(msg)

    # Атомарно инкрементируем thread_count на корневом сообщении (избегаем race condition)
    db.execute(sa_update(Message).where(Message.id == root_msg.id).values(thread_count=Message.thread_count + 1))
    try:
        db.commit()
        db.refresh(msg)
        db.refresh(root_msg)
    except Exception as e:
        db.rollback()
        logger.error("Failed to save thread reply in room %s: %s", room_id, e)
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "Failed to save thread reply",
            },
        )
        return

    # ACK отправителю
    await manager.send_to_user(
        room_id,
        user.id,
        message_ack(client_msg_id, msg.id, _epoch_micros(msg.created_at)),
    )

    # Собираем member_ids для pending delivery
    _thread_member_ids = [
        rm.user_id
        for rm in db.query(RoomMember.user_id)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.is_banned.is_(False),
        )
        .all()
    ]

    # Рассылаем сообщение в тред всем в комнате
    payload = message_thread_sent(
        msg_id=msg.id,
        client_msg_id=client_msg_id,
        thread_id=thread_id,
        ciphertext=ciphertext_hex,
        digest_hex=parsed.digest_hex,
        created_at_us=_epoch_micros(msg.created_at),
        sender_pseudo=msg.sender_pseudo,
        sender=user.username,
        display_name=user.display_name,
        avatar_emoji=user.avatar_emoji,
        avatar_url=user.avatar_url,
        enc_v=enc_v,
        reply_to_id=reply_to_id,
        reply_quote=parsed.reply_quote,
    )
    # BMP-only delivery (WS broadcast removed)
    await _bmp_deposit(room_id, payload)
    await manager.enqueue_pending(room_id, payload, member_ids=_thread_member_ids)

    # Cross-node replication (same opt-in flag as regular messages)
    _room_obj2 = db.query(Room).filter(Room.id == room_id).first()
    if _room_obj2 is not None:
        try:
            _sender_ts2 = int(msg.created_at.timestamp()) if msg.created_at else 0
        except Exception:
            _sender_ts2 = 0
        await _maybe_replicate(_room_obj2, payload, _sender_ts2)

    # Обновляем badge thread_count для всех
    await manager.broadcast_to_room(room_id, message_thread_update(thread_id, root_msg.thread_count))


# Edit message


async def handle_edit_message(room_id: int, user: User, data: dict, db: Session) -> None:
    parsed = _read_envelope(data, "edit_message")
    if parsed.refusal:
        await manager.send_to_user(room_id, user.id, parsed.refusal.frame())
        return

    msg_id = parsed.msg_id
    ciphertext_hex = parsed.ciphertext
    ciphertext_bytes = bytes(parsed.content)

    msg = (
        db.query(Message)
        .filter(
            Message.id == msg_id,
            Message.room_id == room_id,
            Message.msg_type == MessageType.TEXT,
        )
        .first()
    )
    if not msg:
        return
    # Ownership check: prefer sender_pseudo (sealed sender), fall back to sender_id
    _is_owner = (msg.sender_pseudo and verify_sender_pseudo(room_id, user.id, msg.sender_pseudo)) or (
        msg.sender_pseudo is None and msg.sender_id == user.id
    )
    if not _is_owner:
        return

    from app.models_rooms import MessageEditHistory

    # Сохранить предыдущую версию в историю (вместе с её enc_v, чтобы
    # просмотрщик истории мог выбрать правильную схему расшифровки)
    if msg.content_encrypted:
        history_entry = MessageEditHistory(
            message_id=msg.id,
            ciphertext_hex=msg.content_encrypted.hex()
            if isinstance(msg.content_encrypted, (bytes, bytearray))
            else str(msg.content_encrypted),
            enc_version=msg.enc_version,
            edited_at=datetime.now(timezone.utc),
        )
        db.add(history_entry)

    enc_v = parsed.enc_v
    msg.content_encrypted = ciphertext_bytes
    msg.content_hash = bytes(parsed.digest)
    msg.enc_version = enc_v
    msg.is_edited = True
    msg.edited_at = datetime.now(timezone.utc)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to edit message %s: %s", msg_id, e)
        return

    await manager.broadcast_to_room(room_id, message_edited(msg_id, ciphertext_hex, enc_v))


# Delete message


async def handle_delete_message(room_id: int, user: User, data: dict, db: Session) -> None:
    parsed = _read_envelope(data, "delete_message")
    if parsed.refusal:
        await manager.send_to_user(room_id, user.id, parsed.refusal.frame())
        return

    msg_id = parsed.msg_id

    msg = (
        db.query(Message)
        .filter(
            Message.id == msg_id,
            Message.room_id == room_id,
        )
        .first()
    )
    if not msg:
        return
    # Ownership check OR admin/owner role in room
    _is_owner = (msg.sender_pseudo and verify_sender_pseudo(room_id, user.id, msg.sender_pseudo)) or (
        msg.sender_pseudo is None and msg.sender_id == user.id
    )
    if not _is_owner:
        from app.models_rooms import RoomMember, RoomRole

        member = (
            db.query(RoomMember)
            .filter(
                RoomMember.room_id == room_id,
                RoomMember.user_id == user.id,
            )
            .first()
        )
        if not member or member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
            return

    db.delete(msg)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to delete message %s: %s", msg_id, e)
        return

    await manager.broadcast_to_room(room_id, message_deleted(msg_id))
