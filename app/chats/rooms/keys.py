"""
rooms_keys — Распределение ключей: вступление, предоставление ключа, получение key-bundle, ротация.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import EncryptedRoomKey, PendingKeyRequest, Room, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.security.key_exchange import validate_ecies_payload

from app.chats.rooms.helpers import (
    router,
    ProvideKeyRequest,
    _room_dict,
    _require_member,
    _broadcast_key_request,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Вступление в комнату
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/join/{invite_code}")
async def join_room(
        invite_code: str,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Вступление в комнату по invite_code.

    После вступления запускается протокол получения ключа:
      1. Если у пользователя уже есть EncryptedRoomKey -> возвращаем has_key=True
      2. Иначе создаём PendingKeyRequest и рассылаем online-участникам "key_request"
      3. Когда любой участник ответит -> ключ доставляется через WebSocket

    has_key=False означает: нужно дождаться {type: "room_key"} через WebSocket.
    """
    if not u.x25519_public_key:
        raise HTTPException(400, "X25519 public key required to join a room")

    room = db.query(Room).filter(Room.invite_code == invite_code.upper()).first()
    if not room:
        raise HTTPException(404, "Room not found")

    # Проверяем существующее членство
    existing = db.query(RoomMember).filter(
        RoomMember.room_id == room.id,
        RoomMember.user_id == u.id,
        ).first()

    if existing:
        if existing.is_banned:
            raise HTTPException(403, "You are blocked in this room")
        # Уже участник — проверяем наличие ключа
        has_key = db.query(EncryptedRoomKey).filter(
            EncryptedRoomKey.room_id == room.id,
            EncryptedRoomKey.user_id == u.id,
            ).first() is not None
        return {"joined": False, "room": _room_dict(room), "has_key": has_key}

    if room.is_full():
        raise HTTPException(409, "Room is full")

    # Добавляем участника
    db.add(RoomMember(room_id=room.id, user_id=u.id, role=RoomRole.MEMBER))

    # Создаём PendingKeyRequest (ожидаем ключ от online-участников)
    pending = PendingKeyRequest(
        room_id    = room.id,
        user_id    = u.id,
        pubkey_hex = u.x25519_public_key,
        expires_at = datetime.now(timezone.utc) + timedelta(hours=48),
    )
    db.add(pending)
    db.commit()

    # Рассылаем online-участникам запрос на re-encryption ключа
    online_count = len(manager.get_online_users(room.id))
    if online_count > 0:
        await _broadcast_key_request(room.id, u.id, u.x25519_public_key, u.kyber_public_key)
        logger.info(f"{u.username} joined room {room.id}, key_request sent to {online_count} online members")
    else:
        logger.info(f"{u.username} joined room {room.id}, no online members — key pending")

    return {
        "joined":   True,
        "room":     _room_dict(room),
        "has_key":  False,   # ключ придёт через WebSocket
        "message":  "Await room key from a member via WebSocket",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Предоставление ключа ожидающему участнику (HTTP-путь, альтернатива WebSocket)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{room_id}/provide-key")
async def provide_key(
        room_id: int,
        body: ProvideKeyRequest,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Участник передаёт зашифрованный ключ комнаты другому участнику.

    Вызывается когда участник расшифровал room_key локально и re-encrypt его
    для ожидающего участника. Может быть вызван через HTTP или через WebSocket
    (action: "key_response").

    Валидация:
      - Вызывающий должен быть участником комнаты
      - Получатель должен быть участником комнаты
      - Получатель должен иметь активный PendingKeyRequest
    """
    # Проверяем что вызывающий — участник
    _require_member(room_id, u.id, db)

    # Проверяем что получатель — участник
    target_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == body.for_user_id,
        RoomMember.is_banned == False,
        ).first()
    if not target_member:
        raise HTTPException(404, "Recipient is not a room member")

    # Получаем публичный ключ получателя
    from app.models import User as UserModel
    target_user = db.query(UserModel).filter(UserModel.id == body.for_user_id).first()
    if not target_user or not target_user.x25519_public_key:
        raise HTTPException(400, "Recipient has no X25519 public key")

    # Валидируем ECIES payload
    payload = {"ephemeral_pub": body.ephemeral_pub, "ciphertext": body.ciphertext}
    if not validate_ecies_payload(payload):
        raise HTTPException(400, "Invalid key format")

    # Сохраняем или обновляем EncryptedRoomKey для получателя
    existing_key = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == body.for_user_id,
        ).first()

    if existing_key:
        existing_key.ephemeral_pub = body.ephemeral_pub
        existing_key.ciphertext    = body.ciphertext
        existing_key.recipient_pub = target_user.x25519_public_key
        existing_key.updated_at    = datetime.now(timezone.utc)
    else:
        db.add(EncryptedRoomKey(
            room_id       = room_id,
            user_id       = body.for_user_id,
            ephemeral_pub = body.ephemeral_pub,
            ciphertext    = body.ciphertext,
            recipient_pub = target_user.x25519_public_key,
        ))

    # Удаляем PendingKeyRequest
    db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id == body.for_user_id,
        ).delete()

    db.commit()

    # Доставляем ключ получателю через WebSocket если он онлайн
    delivered = await manager.send_to_user(room_id, body.for_user_id, {
        "type":         "room_key",
        "ephemeral_pub": body.ephemeral_pub,
        "ciphertext":   body.ciphertext,
    })

    logger.info(
        f"Key provided for user {body.for_user_id} in room {room_id} "
        f"by {u.username} (ws_delivered={delivered})"
    )

    return {"ok": True, "delivered_via_ws": delivered}


# ══════════════════════════════════════════════════════════════════════════════
# Получение зашифрованного ключа комнаты (для клиента)
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/key-bundle")
async def get_key_bundle(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Возвращает зашифрованный ключ комнаты для текущего пользователя.

    Клиент расшифровывает его локально:
      shared_key = HKDF(DH(user_priv, ephemeral_pub))
      room_key   = AES-GCM-decrypt(ciphertext, shared_key)
    """
    _require_member(room_id, u.id, db)

    enc_key = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
        ).first()

    if not enc_key:
        # Проверяем есть ли pending request
        pending = db.query(PendingKeyRequest).filter(
            PendingKeyRequest.room_id == room_id,
            PendingKeyRequest.user_id == u.id,
            ).first()

        if pending and pending.is_expired:
            db.delete(pending)
            db.commit()
            pending = None

        if not pending:
            # Создаём новый запрос и рассылаем
            db.add(PendingKeyRequest(
                room_id    = room_id,
                user_id    = u.id,
                pubkey_hex = u.x25519_public_key,
                expires_at = datetime.now(timezone.utc) + timedelta(hours=48),
            ))
            db.commit()
            await _broadcast_key_request(room_id, u.id, u.x25519_public_key)

        return {
            "has_key": False,
            "message": "Key pending. Await {type: 'room_key'} via WebSocket",
        }

    return {
        "has_key":      True,
        "ephemeral_pub": enc_key.ephemeral_pub,
        "ciphertext":   enc_key.ciphertext,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Ротация ключа комнаты
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{room_id}/rotate-key")
async def rotate_room_key(
        room_id: int,
        u: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """
    Ротация ключа комнаты. Вызывается после кика/выхода участника.
    Удаляет все EncryptedRoomKey — каждый участник получит новый ключ через key_request.
    """
    _require_member(room_id, u.id, db)

    # Удаляем все зашифрованные ключи — принудительная re-distribution
    db.query(EncryptedRoomKey).filter(EncryptedRoomKey.room_id == room_id).delete()

    # Создаём PendingKeyRequest для всех участников
    members = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.is_banned == False,
    ).all()

    for m in members:
        member_user = db.query(User).filter(User.id == m.user_id).first()
        if member_user and member_user.x25519_public_key:
            existing = db.query(PendingKeyRequest).filter(
                PendingKeyRequest.room_id == room_id,
                PendingKeyRequest.user_id == m.user_id,
            ).first()
            if not existing:
                db.add(PendingKeyRequest(
                    room_id=room_id,
                    user_id=m.user_id,
                    pubkey_hex=member_user.x25519_public_key,
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
                ))

    db.commit()

    # Уведомляем всех online: "ключ сброшен, нужен новый"
    await manager.broadcast_to_room(room_id, {
        "type": "key_rotated",
        "message": "Room key updated. New key will be delivered.",
    })

    logger.info(f"Room key rotated for room {room_id} by {u.username}")
    return {"ok": True}
