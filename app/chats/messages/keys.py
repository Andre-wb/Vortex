"""
app/chats/chat_keys.py — E2E room key delivery, key requests, key responses.

Extracted from chat.py for maintainability.
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import User
from app.models_rooms import (
    EncryptedRoomKey,
    PendingKeyRequest,
    RoomMember,
)
from app.peer.connection_manager import manager
from app.security.wrapped_key_backend import wrapped_key_parse

logger = logging.getLogger(__name__)


def _kyber_req_fields(u: User | None) -> dict:
    """Kyber-pub + подпись реквестера для гибрид-обёртки ответа (пусто, если
    чего-то нет). Отвечающий ОБЯЗАН проверить подпись против припиненного Ed
    реквестера (клиент, resolvePeerKyberPub) — pub из broadcast сам не доверенный."""
    if u and u.kyber_public_key and u.kyber_public_key_sig:
        return {"for_kyber_pubkey": u.kyber_public_key, "for_kyber_sig": u.kyber_public_key_sig}
    return {}


async def deliver_or_request_room_key(room_id: int, user: User, db: Session) -> None:
    enc_key = (
        db.query(EncryptedRoomKey)
        .filter(
            EncryptedRoomKey.room_id == room_id,
            EncryptedRoomKey.user_id == user.id,
        )
        .first()
    )

    if enc_key:
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "room_key",
                "room_id": room_id,
                **enc_key.to_client_dict(),
            },
        )
        return

    if not user.x25519_public_key:
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "X25519 public key not registered",
            },
        )
        return

    # Раздача ключа через key_request (sealed-prekey путь удалён: обёртка шла на
    # one-time pubkey, чей приватный отбрасывался → пакет недекриптуем, а авто-claim
    # создавал сломанный EncryptedRoomKey с has_key=True, навсегда глуша key_request).
    pending = (
        db.query(PendingKeyRequest)
        .filter(
            PendingKeyRequest.room_id == room_id,
            PendingKeyRequest.user_id == user.id,
        )
        .first()
    )

    if not pending or pending.is_expired:
        if pending:
            db.delete(pending)
        db.add(
            PendingKeyRequest(
                room_id=room_id,
                user_id=user.id,
                pubkey_hex=user.x25519_public_key,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
            )
        )
        db.commit()

    await manager.broadcast_to_room(
        room_id,
        {
            "type": "key_request",
            "room_id": room_id,
            "for_user_id": user.id,
            "for_pubkey": user.x25519_public_key,
            **_kyber_req_fields(user),
        },
        exclude=user.id,
    )

    # Также отправляем key_request через notification WS участникам,
    # которые НЕ в этой комнате (но онлайн в приложении).
    # Без этого ключ не передастся, если второй пользователь в другом чате.
    other_members = (
        db.query(RoomMember.user_id)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id != user.id,
        )
        .all()
    )
    # BMP mode: key_request goes through BMP room deposit (not targeted notify)
    from app.config import Config

    _key_req_payload = {
        "type": "key_request",
        "room_id": room_id,
        "for_user_id": user.id,
        "for_pubkey": user.x25519_public_key,
        **_kyber_req_fields(user),
    }
    if Config.BMP_DELIVERY_ENABLED:
        with contextlib.suppress(Exception):
            import json

            from app.transport.blind_mailbox import deposit_envelope

            await deposit_envelope(room_id, json.dumps(_key_req_payload))
    else:
        for (member_id,) in other_members:
            if member_id not in manager._rooms.get(room_id, {}):
                await manager.notify_user(member_id, _key_req_payload)

    await manager.send_to_user(
        room_id,
        user.id,
        {
            "type": "waiting_for_key",
            "message": "\u041e\u0436\u0438\u0434\u0430\u043d\u0438\u0435 \u043a\u043b\u044e\u0447\u0430 \u043a\u043e\u043c\u043d\u0430\u0442\u044b \u043e\u0442 \u0434\u0440\u0443\u0433\u043e\u0433\u043e \u0443\u0447\u0430\u0441\u0442\u043d\u0438\u043a\u0430...",
        },
    )


async def notify_pending_key_requests(room_id: int, user_id: int, db: Session) -> None:
    pending_requests = (
        db.query(PendingKeyRequest)
        .filter(
            PendingKeyRequest.room_id == room_id,
            PendingKeyRequest.user_id != user_id,
            PendingKeyRequest.expires_at > datetime.now(timezone.utc),
        )
        .all()
    )

    for req in pending_requests:
        req_user = db.query(User).filter(User.id == req.user_id).first()
        await manager.send_to_user(
            room_id,
            user_id,
            {
                "type": "key_request",
                "room_id": room_id,
                "for_user_id": req.user_id,
                "for_pubkey": req.pubkey_hex,
                **_kyber_req_fields(req_user),
            },
        )


async def handle_key_response(room_id: int, user: User, data: dict, db: Session) -> None:
    for_user_id = data.get("for_user_id")
    # \u041e\u0431\u0435 \u0444\u043e\u0440\u043c\u044b \u043a\u043e\u043d\u0432\u0435\u0440\u0442\u0430: \u0433\u0438\u0431\u0440\u0438\u0434 (X25519+ML-KEM) \u0438\u043b\u0438 \u043a\u043b\u0430\u0441\u0441\u0438\u043a\u0430. X25519-\u044d\u0444\u0435\u043c\u0435\u0440\u043d\u044b\u0439
    # \u0445\u0440\u0430\u043d\u0438\u0442\u0441\u044f \u0432 \u0435\u0434\u0438\u043d\u043e\u0439 \u043a\u043e\u043b\u043e\u043d\u043a\u0435 ephemeral_pub \u043d\u0435\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e \u043e\u0442 \u0444\u043e\u0440\u043c\u044b.
    wrapped = wrapped_key_parse(json.dumps(data))

    if not for_user_id or wrapped is None:
        await manager.send_to_user(
            room_id,
            user.id,
            {
                "type": "error",
                "message": "\u041d\u0435\u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u0439 key_response \u0444\u043e\u0440\u043c\u0430\u0442",
            },
        )
        return

    target_member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == for_user_id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not target_member:
        return

    from app.models import User as UserModel

    target_user = db.query(UserModel).filter(UserModel.id == for_user_id).first()

    existing = (
        db.query(EncryptedRoomKey)
        .filter(
            EncryptedRoomKey.room_id == room_id,
            EncryptedRoomKey.user_id == for_user_id,
        )
        .first()
    )

    if existing:
        existing.ephemeral_pub = wrapped.ephemeral_pub
        existing.ciphertext = wrapped.ciphertext
        existing.kyber_ciphertext = wrapped.kyber_ciphertext
        existing.updated_at = datetime.now(timezone.utc)
    else:
        db.add(
            EncryptedRoomKey(
                room_id=room_id,
                user_id=for_user_id,
                ephemeral_pub=wrapped.ephemeral_pub,
                ciphertext=wrapped.ciphertext,
                kyber_ciphertext=wrapped.kyber_ciphertext,
                recipient_pub=target_user.x25519_public_key if target_user else None,
            )
        )

    db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id == for_user_id,
    ).delete()

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to save key_response for user %s room %s: %s", for_user_id, room_id, e)
        return

    key_payload = {
        "type": "room_key",
        "room_id": room_id,
        **wrapped.client_dict(),
    }

    delivered = await manager.send_to_user(room_id, for_user_id, key_payload)

    # If room WS delivery failed, try notification WS (user may be in another chat)
    if not delivered:
        await manager.notify_user(for_user_id, key_payload)

    logger.info(
        f"Key re-encrypted by {user.username} for user {for_user_id} in room {room_id} (ws_delivered={delivered})"
    )
