"""
app/chats/chat_history.py — Send message history to a user upon WS connection.

Extracted from chat.py for maintainability.
"""
from __future__ import annotations

import json
import logging

from sqlalchemy.orm import Session

from app.models import User
from app.models_rooms import (
    FileTransfer, Message, MessageReaction, MessageType, Room, RoomMember,
)
from app.peer.connection_manager import manager

from app.chats.messages._router import utc_iso as _utc_iso
from app.security.sealed_sender import compute_sender_pseudo as _compute_pseudo

logger = logging.getLogger(__name__)


async def send_history(room_id: int, user_id: int, db: Session) -> None:
    # Исключаем сообщения, принадлежащие тредам (thread_id != None),
    # чтобы в основном чате показывались только корневые сообщения.
    messages = (
        db.query(Message)
        .filter(Message.room_id == room_id, Message.thread_id.is_(None))
        .order_by(Message.created_at.desc())
        .limit(50).all()
    )[::-1]

    # Загружаем реакции для всех сообщений пакетно
    msg_ids = [m.id for m in messages]
    reactions_map: dict[int, list] = {}
    if msg_ids:
        all_reactions = (
            db.query(MessageReaction, User)
            .join(User, User.id == MessageReaction.user_id)
            .filter(MessageReaction.message_id.in_(msg_ids))
            .all()
        )
        for r, u in all_reactions:
            reactions_map.setdefault(r.message_id, []).append({
                "user_id":      r.user_id,
                "emoji":        r.emoji,
                "username":     u.username,
                "display_name": u.display_name or u.username,
                "created_at":   r.created_at.isoformat() + "Z" if r.created_at else None,
            })

    # Получаем информацию о прочтении для подсчёта статуса
    room_members = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
    ).all()

    # Build pseudo→user_id map for sealed-sender resolution
    _pseudo_to_uid: dict[str, int] = {
        _compute_pseudo(room_id, rm.user_id): rm.user_id
        for rm in room_members
    }

    # Build uid→User cache for display names (sealed sender may null .sender)
    _member_uids = [rm.user_id for rm in room_members]
    _uid_to_user: dict[int, User] = {
        u.id: u for u in db.query(User).filter(User.id.in_(_member_uids)).all()
    } if _member_uids else {}

    # Build uid→tag map for member tags
    _uid_to_tag: dict[int, tuple[str | None, str | None]] = {
        rm.user_id: (getattr(rm, 'tag', None), getattr(rm, 'tag_color', None))
        for rm in room_members
    }

    history = []
    for m in messages:
        # Пропускаем запланированные сообщения
        if m.is_scheduled:
            continue

        # Опросы (Feature 1) — передаём как poll
        if m.msg_type == MessageType.SYSTEM and m.content_encrypted:
            try:
                poll_data = json.loads(m.content_encrypted.decode())
                if "question" in poll_data and "options" in poll_data:
                    _poll_sender_id = (
                        _pseudo_to_uid.get(m.sender_pseudo)
                        if m.sender_pseudo
                        else m.sender_id
                    )
                    _poll_user = m.sender or _uid_to_user.get(_poll_sender_id)
                    history.append({
                        "type": "poll",
                        "msg_id": m.id,
                        "sender_id": _poll_sender_id,
                        "sender_pseudo": m.sender_pseudo,
                        "sender": _poll_user.username if _poll_user else "?",
                        "display_name": (_poll_user.display_name or _poll_user.username) if _poll_user else "?",
                        "avatar_emoji": _poll_user.avatar_emoji if _poll_user else "\U0001F464",
                        "question": poll_data["question"],
                        "options": poll_data["options"],
                        "votes": poll_data.get("votes", {}),
                        "voters": poll_data.get("voters", {}),
                        "created_at": _utc_iso(m.created_at),
                    })
                    continue
            except Exception:
                pass

        # Resolve sender user_id from sealed-sender pseudo or fallback
        _resolved_sender_id = (
            _pseudo_to_uid.get(m.sender_pseudo)
            if m.sender_pseudo
            else m.sender_id
        )
        _user = m.sender or _uid_to_user.get(_resolved_sender_id)
        _sender_is_bot = bool(_user and _user.is_bot)
        _tag_info = _uid_to_tag.get(_resolved_sender_id, (None, None)) if _resolved_sender_id else (None, None)
        entry = {
            **m.to_relay_dict(),
            "type":         "history_msg",
            "sender_id":    _resolved_sender_id,
            "sender":       _user.username      if _user else "?",
            "display_name": (_user.display_name or _user.username) if _user else "?",
            "avatar_emoji": _user.avatar_emoji   if _user else "\U0001F464",
            "avatar_url":   _user.avatar_url     if _user else None,
            "is_bot":       _sender_is_bot,
            "tag":          _tag_info[0],
            "tag_color":    _tag_info[1],
            "status":       "sent",
            "reactions":    reactions_map.get(m.id, []),
        }
        # Bot messages are stored as plaintext — include decoded text
        if _sender_is_bot and m.content_encrypted:
            try:
                entry["plaintext"] = m.content_encrypted.decode("utf-8")
            except Exception:
                pass
        # Вычисляем статус прочтения
        # Resolve sender's user_id via pseudo (sealed sender) or fallback to sender_id
        _sender_uid = (
            _pseudo_to_uid.get(m.sender_pseudo)
            if m.sender_pseudo
            else m.sender_id
        )
        read_by_others = any(
            rm.last_read_message_id and rm.last_read_message_id >= m.id
            for rm in room_members if rm.user_id != _sender_uid
        )
        if read_by_others:
            entry["status"] = "read"

        if m.msg_type in (MessageType.IMAGE, MessageType.FILE, MessageType.VOICE):
            # Resolve uploader_id via pseudo (sealed sender) or fallback
            _uploader_id = (
                _pseudo_to_uid.get(m.sender_pseudo)
                if m.sender_pseudo
                else m.sender_id
            )
            ft = db.query(FileTransfer).filter(
                FileTransfer.room_id       == room_id,
                FileTransfer.original_name == m.file_name,
                FileTransfer.uploader_id   == _uploader_id,
            ).order_by(FileTransfer.created_at.desc()).first()

            if ft:
                entry["download_url"] = f"/api/files/download/{ft.id}"
                entry["mime_type"]    = ft.mime_type
                entry["file_hash"]    = ft.file_hash

        history.append(entry)

    # Получаем закреплённое сообщение
    room_obj = db.query(Room).filter(Room.id == room_id).first()
    pinned_id = room_obj.pinned_message_id if room_obj else None
    pinned_text = None
    pinned_sender = None
    if pinned_id:
        _pinned_msg = db.query(Message).filter(Message.id == pinned_id).first()
        if _pinned_msg:
            # Text is encrypted — send ciphertext hex for client-side decryption
            pinned_text = _pinned_msg.content_encrypted.hex() if _pinned_msg.content_encrypted else None
            pinned_sender = _pinned_msg.sender.display_name or _pinned_msg.sender.username if _pinned_msg.sender else None

    # Определяем, является ли собеседник контактом (для DM)
    is_contact_flag = True
    other_user_id = None
    is_dm = room_obj.is_dm if room_obj else False

    if is_dm and room_obj:
        other_member = db.query(RoomMember).filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id != user_id,
        ).first()
        if other_member:
            other_user_id = other_member.user_id
            from app.models.contact import Contact
            is_contact_flag = db.query(Contact).filter(
                Contact.owner_id == user_id,
                Contact.contact_id == other_member.user_id,
            ).first() is not None

    await manager.send_to_user(room_id, user_id, {
        "type":              "history",
        "messages":          history,
        "pinned_message_id": pinned_id,
        "pinned_message_ciphertext": pinned_text,
        "pinned_message_sender": pinned_sender,
        "auto_delete_seconds": room_obj.auto_delete_seconds if room_obj else None,
        "slow_mode_seconds":   room_obj.slow_mode_seconds if room_obj else 0,
        "is_dm":               is_dm,
        "other_user_is_contact": is_contact_flag,
        "other_user_id":       other_user_id,
    })
