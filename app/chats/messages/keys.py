"""
app/chats/chat_keys.py — E2E room key delivery, key requests, key responses.

Extracted from chat.py for maintainability.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import User
from app.models_rooms import (
    EncryptedRoomKey, PendingKeyRequest, RoomMember,
)
from app.peer.connection_manager import manager
from app.security.key_exchange import validate_ecies_payload

logger = logging.getLogger(__name__)


async def deliver_or_request_room_key(room_id: int, user: User, db: Session) -> None:
    enc_key = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == user.id,
    ).first()

    if enc_key:
        await manager.send_to_user(room_id, user.id, {
            "type":          "room_key",
            "room_id":       room_id,
            "ephemeral_pub": enc_key.ephemeral_pub,
            "ciphertext":    enc_key.ciphertext,
        })
        return

    if not user.x25519_public_key:
        await manager.send_to_user(room_id, user.id, {
            "type":    "error",
            "message": "\u0423 \u0432\u0430\u0441 \u043d\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d X25519 \u043f\u0443\u0431\u043b\u0438\u0447\u043d\u044b\u0439 \u043a\u043b\u044e\u0447",
        })
        return

    pending = db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id == user.id,
    ).first()

    if not pending or pending.is_expired:
        if pending:
            db.delete(pending)
        db.add(PendingKeyRequest(
            room_id    = room_id,
            user_id    = user.id,
            pubkey_hex = user.x25519_public_key,
            expires_at = datetime.now(timezone.utc) + timedelta(hours=48),
        ))
        db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":        "key_request",
        "for_user_id": user.id,
        "for_pubkey":  user.x25519_public_key,
    }, exclude=user.id)

    # Также отправляем key_request через notification WS участникам,
    # которые НЕ в этой комнате (но онлайн в приложении).
    # Без этого ключ не передастся, если второй пользователь в другом чате.
    other_members = db.query(RoomMember.user_id).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id != user.id,
    ).all()
    for (member_id,) in other_members:
        if member_id not in manager._rooms.get(room_id, {}):
            await manager.notify_user(member_id, {
                "type":        "key_request",
                "room_id":     room_id,
                "for_user_id": user.id,
                "for_pubkey":  user.x25519_public_key,
            })

    await manager.send_to_user(room_id, user.id, {
        "type":    "waiting_for_key",
        "message": "\u041e\u0436\u0438\u0434\u0430\u043d\u0438\u0435 \u043a\u043b\u044e\u0447\u0430 \u043a\u043e\u043c\u043d\u0430\u0442\u044b \u043e\u0442 \u0434\u0440\u0443\u0433\u043e\u0433\u043e \u0443\u0447\u0430\u0441\u0442\u043d\u0438\u043a\u0430...",
    })


async def notify_pending_key_requests(room_id: int, user_id: int, db: Session) -> None:
    pending_requests = db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id != user_id,
        PendingKeyRequest.expires_at > datetime.now(timezone.utc),
    ).all()

    for req in pending_requests:
        await manager.send_to_user(room_id, user_id, {
            "type":        "key_request",
            "for_user_id": req.user_id,
            "for_pubkey":  req.pubkey_hex,
        })


async def handle_key_response(room_id: int, user: User, data: dict, db: Session) -> None:
    for_user_id   = data.get("for_user_id")
    ephemeral_pub = data.get("ephemeral_pub", "")
    ciphertext    = data.get("ciphertext", "")

    if not for_user_id or not validate_ecies_payload({"ephemeral_pub": ephemeral_pub, "ciphertext": ciphertext}):
        await manager.send_to_user(room_id, user.id, {
            "type": "error", "message": "\u041d\u0435\u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u0439 key_response \u0444\u043e\u0440\u043c\u0430\u0442"
        })
        return

    target_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == for_user_id,
        RoomMember.is_banned == False,
    ).first()
    if not target_member:
        return

    from app.models import User as UserModel
    target_user = db.query(UserModel).filter(UserModel.id == for_user_id).first()

    existing = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == for_user_id,
    ).first()

    if existing:
        existing.ephemeral_pub = ephemeral_pub
        existing.ciphertext    = ciphertext
        existing.updated_at    = datetime.now(timezone.utc)
    else:
        db.add(EncryptedRoomKey(
            room_id       = room_id,
            user_id       = for_user_id,
            ephemeral_pub = ephemeral_pub,
            ciphertext    = ciphertext,
            recipient_pub = target_user.x25519_public_key if target_user else None,
        ))

    db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id == for_user_id,
    ).delete()

    db.commit()

    delivered = await manager.send_to_user(room_id, for_user_id, {
        "type":          "room_key",
        "room_id":       room_id,
        "ephemeral_pub": ephemeral_pub,
        "ciphertext":    ciphertext,
    })

    logger.info(
        f"Key re-encrypted by {user.username} for user {for_user_id} "
        f"in room {room_id} (ws_delivered={delivered})"
    )
