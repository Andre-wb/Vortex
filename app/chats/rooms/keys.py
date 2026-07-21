"""
rooms_keys — Распределение ключей: вступление, предоставление ключа, получение key-bundle, ротация.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.models import User
from app.models_rooms import EncryptedRoomKey, PendingKeyRequest, Room, RoomMember, RoomRole, JoinRequest, RoomInvite, RoomInviteEscrow
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.security.key_exchange import validate_ecies_payload
from app.security.ecies_schema import EciesKeyFields

from app.chats.rooms.helpers import (
    router,
    ProvideKeyRequest,
    EncryptedKeyPayload,
    _room_dict,
    _require_member,
    _broadcast_key_request,
    _approval_enforced,
    _can_admit,
    _invalidate_room_escrows,
)


class ProvisionKeyRequest(EciesKeyFields):
    """Directed pre-wrap: член заранее оборачивает room key для юзера X (классика
    или post-quantum гибрид, EciesKeyFields), чтобы X забрал ключ оффлайн."""
    for_user_id: int

logger = logging.getLogger(__name__)


# Вступление в комнату

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

    # join_approval (энфорс за Config-флагом): создаём pending-заявку, НЕ добавляем
    # участником — заявитель невидим для _require_member, пока админ не одобрит.
    if _approval_enforced(room):
        existing_req = db.query(JoinRequest).filter(
            JoinRequest.room_id == room.id,
            JoinRequest.user_id == u.id,
        ).first()
        if not existing_req:
            db.add(JoinRequest(room_id=room.id, user_id=u.id, x25519_pub=u.x25519_public_key))
            db.commit()
        return {"joined": False, "pending": True, "room": _room_dict(room), "has_key": False,
                "message": "Join request awaiting admin approval"}

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
        await _broadcast_key_request(room.id, u.id, u.x25519_public_key,
                                     u.kyber_public_key, u.kyber_public_key_sig)
        logger.info(f"{u.username} joined room {room.id}, key_request sent to {online_count} online members")
    else:
        logger.info(f"{u.username} joined room {room.id}, no online members — key pending")

    return {
        "joined":   True,
        "room":     _room_dict(room),
        "has_key":  False,   # ключ придёт через WebSocket
        "message":  "Await room key from a member via WebSocket",
    }


# Предоставление ключа ожидающему участнику (HTTP-путь, альтернатива WebSocket)

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


# Directed pre-provision: раздача ключа новому участнику ОФФЛАЙН
# (когда никто из членов не онлайн, чтобы ответить на key_request).

@router.post("/{room_id}/provision-key")
async def provision_key(
        room_id: int,
        body:    ProvisionKeyRequest,
        u:       User    = Depends(get_current_user),
        db:      Session = Depends(get_db),
):
    """
    Член с ключом заранее оборачивает room key для юзера X и добавляет X
    участником — X заберёт ключ через key-bundle оффлайн, даже когда никто из
    членов не онлайн. Не перетирает уже существующий ключ X (skip-if-exists).

    Self-heal (ADR-005 §4.0): если провижн-ключ негоден, клиент X удаляет его
    через DELETE /{room_id}/my-key → падает в key_request.
    """
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")

    # Вызывающий — участник, который САМ держит ключ (иначе провижнить нечего)
    actor = _require_member(room_id, u.id, db)
    caller_has_key = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
    ).first()
    if not caller_has_key:
        raise HTTPException(403, "No room key — cannot provision for others")

    target = db.query(User).filter(
        User.id == body.for_user_id, User.is_active == True,
    ).first()
    if not target or not target.x25519_public_key:
        raise HTTPException(400, "Recipient not found or has no X25519 key")

    if not validate_ecies_payload(body.ecies_dict()):
        raise HTTPException(400, "Invalid key format")

    # Добавляем X участником (если ещё нет и не забанен)
    target_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == body.for_user_id,
    ).first()
    if target_member and target_member.is_banned:
        raise HTTPException(403, "Recipient is banned")
    newly_added = False
    if not target_member:
        # Согласование с апрувом (ADR-005 O3): обычный член НЕ может добавить нового
        # участника в комнату с энфорс-апрувом (иначе тривиальный обход апрува через
        # provision-key). ADMIN/OWNER — можно (они и есть апрув-инстанция). Единый
        # предикат _can_admit — тот же, что в approve-join.
        if not _can_admit(actor, room):
            raise HTTPException(403, "Join approval required — only admins can add members")
        if room.is_full():
            raise HTTPException(409, "Room is full")
        db.add(RoomMember(room_id=room_id, user_id=body.for_user_id, role=RoomRole.MEMBER))
        newly_added = True
        # Если у добавляемого была pending-заявка — админ впустил его напрямую, чистим её
        db.query(JoinRequest).filter(
            JoinRequest.room_id == room_id,
            JoinRequest.user_id == body.for_user_id,
        ).delete()

    # Не перетираем рабочий ключ X — только провижним отсутствующий
    existing = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == body.for_user_id,
    ).first()
    if existing:
        if newly_added:
            db.commit()
        return {"ok": True, "already_has_key": True, "added": newly_added}

    db.add(EncryptedRoomKey(
        room_id          = room_id,
        user_id          = body.for_user_id,
        ephemeral_pub    = body.eph_pub,
        ciphertext       = body.ciphertext,
        kyber_ciphertext = body.kyber_ciphertext,
        recipient_pub    = target.x25519_public_key,
    ))
    db.query(PendingKeyRequest).filter(
        PendingKeyRequest.room_id == room_id,
        PendingKeyRequest.user_id == body.for_user_id,
    ).delete()
    db.commit()

    # Доставляем сразу, если X онлайн; иначе он заберёт через key-bundle
    delivered = await manager.send_to_user(room_id, body.for_user_id, {
        "type":    "room_key",
        "room_id": room_id,
        **body.ecies_dict(),
    })
    if newly_added:
        await manager.notify_user(body.for_user_id, {
            "type": "added_to_room", "room": _room_dict(room),
        })

    logger.info(f"Key provisioned for user {body.for_user_id} in room {room_id} by {u.username}")
    return {"ok": True, "added": newly_added, "delivered_via_ws": bool(delivered)}


@router.delete("/{room_id}/my-key")
async def forget_my_key(
        room_id: int,
        u:       User    = Depends(get_current_user),
        db:      Session = Depends(get_db),
):
    """
    Self-heal (ADR-005 §4.0): участник удаляет СВОЙ негодный room key (провижн/
    escrow не расшифровался) и заново запрашивает его через key_request. Без
    этого сломанный ключ с has_key=True навсегда глушил бы восстановление
    (тот же лок-аут, что удалённые sealed-prekeys).
    """
    _require_member(room_id, u.id, db)

    deleted = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
    ).delete()

    if u.x25519_public_key:
        already = db.query(PendingKeyRequest).filter(
            PendingKeyRequest.room_id == room_id,
            PendingKeyRequest.user_id == u.id,
        ).first()
        if not already:
            db.add(PendingKeyRequest(
                room_id    = room_id,
                user_id    = u.id,
                pubkey_hex = u.x25519_public_key,
                expires_at = datetime.now(timezone.utc) + timedelta(hours=48),
            ))
    db.commit()

    if u.x25519_public_key and len(manager.get_online_users(room_id)) > 0:
        await _broadcast_key_request(room_id, u.id, u.x25519_public_key,
                                     u.kyber_public_key, u.kyber_public_key_sig)

    logger.info(f"User {u.id} forgot room key in room {room_id} (deleted={deleted}) — re-requesting")
    return {"ok": True, "deleted": bool(deleted)}


# Join-approval workflow (энфорс за Config.JOIN_APPROVAL_ENFORCED)

class ApproveJoinRequest(BaseModel):
    user_id: int
    # Опционально: админ pre-wrap'ает room key для заявителя (оффлайн-доставка).
    # Нет ключа → заявитель получит его через key_request (online-путь).
    encrypted_room_key: EncryptedKeyPayload | None = None


class RejectJoinRequest(BaseModel):
    user_id: int


@router.get("/{room_id}/join-requests")
async def list_join_requests(
        room_id: int,
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Список ожидающих заявок (для ADMIN/OWNER). Несёт kyber-pub+sig заявителя,
    чтобы клиент админа мог гибридно pre-wrap'нуть при одобрении."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    actor = _require_member(room_id, u.id, db)
    if not _can_admit(actor, room):
        raise HTTPException(403, "Only admins can view join requests")

    reqs = db.query(JoinRequest).filter(JoinRequest.room_id == room_id).all()
    result = []
    for r in reqs:
        ru = db.query(User).filter(User.id == r.user_id).first()
        result.append({
            "user_id":              r.user_id,
            "username":             ru.username if ru else None,
            "x25519_public_key":    r.x25519_pub or (ru.x25519_public_key if ru else None),
            "kyber_public_key":     ru.kyber_public_key if ru else None,
            "kyber_public_key_sig": ru.kyber_public_key_sig if ru else None,
            "created_at":           r.created_at.isoformat() if r.created_at else None,
        })
    return {"requests": result}


@router.post("/{room_id}/approve-join")
async def approve_join(
        room_id: int,
        body:    ApproveJoinRequest,
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """ADMIN/OWNER одобряет заявку: добавляет участника + (опц.) pre-wrap ключа →
    заявитель заберёт оффлайн. Единый предикат _can_admit (тот же, что provision-key)."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    actor = _require_member(room_id, u.id, db)
    if not _can_admit(actor, room):
        raise HTTPException(403, "Only admins can approve join requests")

    req = db.query(JoinRequest).filter(
        JoinRequest.room_id == room_id,
        JoinRequest.user_id == body.user_id,
    ).first()
    if not req:
        raise HTTPException(404, "No pending join request for this user")

    target = db.query(User).filter(User.id == body.user_id, User.is_active == True).first()
    if not target or not target.x25519_public_key:
        db.delete(req)
        db.commit()
        raise HTTPException(400, "Requester not found or has no X25519 key")

    # Добавляем участником (если ещё нет и не забанен)
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == body.user_id,
    ).first()
    if member and member.is_banned:
        raise HTTPException(403, "Requester is banned")
    newly_added = False
    if not member:
        if room.is_full():
            raise HTTPException(409, "Room is full")
        db.add(RoomMember(room_id=room_id, user_id=body.user_id, role=RoomRole.MEMBER))
        newly_added = True

    # Опциональный pre-wrap ключа (skip-if-exists — не перетираем рабочий)
    key_stored = False
    ek = body.encrypted_room_key
    if ek and validate_ecies_payload(ek.ecies_dict()):
        existing_key = db.query(EncryptedRoomKey).filter(
            EncryptedRoomKey.room_id == room_id,
            EncryptedRoomKey.user_id == body.user_id,
        ).first()
        if not existing_key:
            db.add(EncryptedRoomKey(
                room_id          = room_id,
                user_id          = body.user_id,
                ephemeral_pub    = ek.eph_pub,
                ciphertext       = ek.ciphertext,
                kyber_ciphertext = ek.kyber_ciphertext,
                recipient_pub    = target.x25519_public_key,
            ))
            db.query(PendingKeyRequest).filter(
                PendingKeyRequest.room_id == room_id,
                PendingKeyRequest.user_id == body.user_id,
            ).delete()
            key_stored = True

    db.delete(req)
    db.commit()

    if key_stored:
        await manager.send_to_user(room_id, body.user_id, {
            "type": "room_key", "room_id": room_id, **ek.ecies_dict(),
        })
    if newly_added:
        await manager.notify_user(body.user_id, {
            "type": "added_to_room", "room": _room_dict(room),
        })

    logger.info(f"Join approved for user {body.user_id} in room {room_id} by {u.username} (key_stored={key_stored})")
    return {"ok": True, "approved": True, "added": newly_added, "key_stored": key_stored}


@router.post("/{room_id}/reject-join")
async def reject_join(
        room_id: int,
        body:    RejectJoinRequest,
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """ADMIN/OWNER отклоняет заявку (просто удаляет — заявитель не становится членом)."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    actor = _require_member(room_id, u.id, db)
    if not _can_admit(actor, room):
        raise HTTPException(403, "Only admins can reject join requests")

    deleted = db.query(JoinRequest).filter(
        JoinRequest.room_id == room_id,
        JoinRequest.user_id == body.user_id,
    ).delete()
    db.commit()
    return {"ok": True, "rejected": bool(deleted)}


# Получение зашифрованного ключа комнаты (для клиента)

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
            await _broadcast_key_request(room_id, u.id, u.x25519_public_key,
                                         u.kyber_public_key, u.kyber_public_key_sig)

        return {
            "has_key": False,
            "message": "Key pending. Await {type: 'room_key'} via WebSocket",
        }

    return {
        "has_key": True,
        **enc_key.to_client_dict(),
    }


# Ротация ключа комнаты

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
    _invalidate_room_escrows(room_id, db)   # escrow'ы на старый ключ устарели

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


# Invite-escrow: offline-join по анонимной ссылке (ADR-005 O4). Член оборачивает
# room key на invite-pub из ссылки; вступающий (УЖЕ член — double-gate) забирает и
# расшифровывает фрагмент-priv. Endpoints дормантны (клиент не зовёт до O5/O6);
# invalidation на ротации — live (no-op пока escrow'ов нет).

class InviteEscrowRequest(EciesKeyFields):
    invite_pub:       str = Field(..., min_length=64, max_length=64)   # X25519 invite pub
    invite_kyber_pub: str | None = None                                # ML-KEM invite pub (PQ)


def _invite_expired(invite) -> bool:
    """TTL-проверка инвайта (ADR-005 O7), tz-робастно (SQLite отдаёт naive-datetime).
    NULL expires_at = без TTL (не истекает)."""
    exp = getattr(invite, "expires_at", None)
    if exp is None:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > exp


@router.post("/{room_id}/invite-escrow")
async def store_invite_escrow(
        room_id: int,
        body:    InviteEscrowRequest,
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Член с ключом сохраняет escrow — room key, обёрнутый на invite-pub. Upsert
    по (room_id, invite_pub). Сервер НЕ видит room key/invite-priv (только релеит)."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    _require_member(room_id, u.id, db)
    caller_has_key = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
    ).first()
    if not caller_has_key:
        raise HTTPException(403, "No room key — cannot create escrow")
    if not validate_ecies_payload(body.ecies_dict()):
        raise HTTPException(400, "Invalid key format")

    # Upsert личность инвайта (персистит через ротацию) — invite_pub + Kyber-pub.
    invite = db.query(RoomInvite).filter(
        RoomInvite.room_id == room_id,
        RoomInvite.invite_pub == body.invite_pub,
    ).first()
    if invite:
        # re-wrap: обновляем только PQ-pub; expires_at НЕ сбрасываем (иначе
        # постоянный re-wrap продлевал бы утёкшую ссылку бесконечно).
        invite.invite_kyber_pub = body.invite_kyber_pub
    else:
        ttl_h = getattr(Config, "INVITE_ESCROW_TTL_HOURS", 168)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_h)) if ttl_h and ttl_h > 0 else None
        db.add(RoomInvite(
            room_id          = room_id,
            invite_pub       = body.invite_pub,
            invite_kyber_pub = body.invite_kyber_pub,
            expires_at       = expires_at,
        ))

    # Upsert обёртку (её удаляет ротация)
    esc = db.query(RoomInviteEscrow).filter(
        RoomInviteEscrow.room_id == room_id,
        RoomInviteEscrow.invite_pub == body.invite_pub,
    ).first()
    if esc:
        esc.ephemeral_pub    = body.eph_pub
        esc.ciphertext       = body.ciphertext
        esc.kyber_ciphertext = body.kyber_ciphertext
    else:
        db.add(RoomInviteEscrow(
            room_id          = room_id,
            invite_pub       = body.invite_pub,
            ephemeral_pub    = body.eph_pub,
            ciphertext       = body.ciphertext,
            kyber_ciphertext = body.kyber_ciphertext,
        ))
    db.commit()
    logger.info(f"Invite escrow stored for room {room_id} (invite_pub={body.invite_pub[:8]}…)")
    return {"ok": True}


@router.get("/{room_id}/invites")
async def list_room_invites(
        room_id: int,
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Активные invite-личности комнаты (для re-wrap на ротации: онлайн-член берёт
    invite_pub'ы и заново оборачивает room key для них). Гейтится членством."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    _require_member(room_id, u.id, db)
    invites = db.query(RoomInvite).filter(RoomInvite.room_id == room_id).all()
    return {"invites": [
        {"invite_pub": iv.invite_pub, "invite_kyber_pub": iv.invite_kyber_pub}
        for iv in invites if not _invite_expired(iv)   # истёкшие не ре-армим (O7 TTL)
    ]}


@router.get("/{room_id}/invite-escrow")
async def get_invite_escrow(
        room_id:    int,
        invite_pub: str = Query(..., min_length=64, max_length=64),
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Вступающий (УЖЕ член — double-gate: сервер гейтит FETCH по ЧЛЕНСТВУ, фрагмент-
    priv гейтит DECRYPT) забирает escrow по invite_pub из ссылки. `_require_member`
    (не владение ссылкой!) — иначе double-gate схлопывается в single-gate и pending-
    заявитель (O3) обошёл бы апрув."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    _require_member(room_id, u.id, db)   # ЛОАД-БЕАРИНГ: членство, не ссылка

    # TTL (O7): истёкший/отсутствующий инвайт → escrow трактуется как отсутствующий.
    invite = db.query(RoomInvite).filter(
        RoomInvite.room_id == room_id,
        RoomInvite.invite_pub == invite_pub,
    ).first()
    if not invite or _invite_expired(invite):
        return {"has_escrow": False}

    esc = db.query(RoomInviteEscrow).filter(
        RoomInviteEscrow.room_id == room_id,
        RoomInviteEscrow.invite_pub == invite_pub,
    ).first()
    if not esc:
        return {"has_escrow": False}
    return {"has_escrow": True, **esc.to_client_dict()}


@router.delete("/{room_id}/invite-escrow")
async def revoke_invite_escrow(
        room_id:    int,
        invite_pub: str = Query(..., min_length=64, max_length=64),
        u:  User    = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Отзыв инвайта (при утечке ссылки). Удаляет И личность (`RoomInvite`), И
    обёртку — иначе на следующей ротации член re-wrap'нул бы escrow заново и утёкшая
    ссылка ожила бы. Не заменяет ротацию room key (утёкший фрагмент видел старый ключ)."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    _require_member(room_id, u.id, db)
    db.query(RoomInviteEscrow).filter(
        RoomInviteEscrow.room_id == room_id,
        RoomInviteEscrow.invite_pub == invite_pub,
    ).delete()
    deleted = db.query(RoomInvite).filter(
        RoomInvite.room_id == room_id,
        RoomInvite.invite_pub == invite_pub,
    ).delete()
    db.commit()
    return {"ok": True, "revoked": bool(deleted)}
