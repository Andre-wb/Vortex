"""
app/security/key_backup.py — Зашифрованный бэкап ключей и синхронизация между устройствами.

Бэкап ключей:
  - Клиент шифрует ВСЕ ключи (x25519 priv, room keys) одним AES-256-GCM ключом,
    производным от пользовательской парольной фразы через PBKDF2-SHA256 (600k итераций).
  - Сервер хранит ТОЛЬКО зашифрованный blob + salt. Расшифровка возможна только на клиенте.
  - Один бэкап на пользователя (upsert). Версионирование для миграций формата.

Связывание устройств (device linking):
  1. Новое устройство: POST /link/request → получает link_code (6 цифр, 10 мин TTL)
  2. Старое устройство: GET /link/{code} → видит запрос + X25519 pub нового устройства
  3. Старое устройство: POST /link/{code}/approve → шифрует ключи ECIES для нового устройства
  4. Новое устройство: GET /link/poll/{request_id} → получает зашифрованные ключи
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models.user import (
    KeyBackup, DeviceLinkRequest, SyncEvent, DeviceCrossSign,
    SecretShare, FederatedBackupShard, KeyTransparencyEntry,
)
from app.security.auth_jwt import get_current_user
from app.security.crypto import hash_token, verify_token_hash
from app.security.ssl_context import make_peer_ssl_context

logger = logging.getLogger(__name__)

_peer_ssl_ctx = make_peer_ssl_context()

router = APIRouter(prefix="/api/keys", tags=["key-backup"])

_LINK_CODE_TTL_MIN = 10
_MAX_LINK_ATTEMPTS = 5


def _is_peer_ip(ip: str) -> bool:
    """Return True if *ip* belongs to a private/loopback range (RFC-1918, localhost)."""
    if ip in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════════════════════════

class BackupUploadRequest(BaseModel):
    vault_data: str = Field(..., min_length=24, description="hex: nonce(12) + AES-256-GCM ciphertext")
    vault_salt: str = Field(..., min_length=32, max_length=64, description="hex salt for KDF")
    kdf_params: str = Field(
        '{"alg":"PBKDF2","iter":600000,"hash":"SHA-256"}',
        description="JSON KDF parameters",
    )


class LinkRequestCreate(BaseModel):
    new_device_pub: str = Field(..., min_length=64, max_length=64, description="X25519 pub hex of new device")


class LinkApproveRequest(BaseModel):
    encrypted_keys: str = Field(..., min_length=24, description="ECIES encrypted key bundle (hex)")


# ══════════════════════════════════════════════════════════════════════════════
# Key Backup CRUD
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/backup", status_code=200)
async def upload_backup(
    body: BackupUploadRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Загрузить/обновить зашифрованный бэкап ключей."""
    try:
        bytes.fromhex(body.vault_data)
        bytes.fromhex(body.vault_salt)
    except ValueError:
        raise HTTPException(400, "vault_data and vault_salt must be valid hex")

    existing = db.query(KeyBackup).filter(KeyBackup.user_id == user.id).first()
    if existing:
        existing.vault_data = body.vault_data
        existing.vault_salt = body.vault_salt
        existing.kdf_params = body.kdf_params
        existing.version = (existing.version or 0) + 1
        existing.updated_at = datetime.now(timezone.utc)
    else:
        backup = KeyBackup(
            user_id=user.id,
            vault_data=body.vault_data,
            vault_salt=body.vault_salt,
            kdf_params=body.kdf_params,
        )
        db.add(backup)
    db.commit()
    return {"ok": True, "message": "Backup saved"}


@router.get("/backup")
async def download_backup(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Скачать зашифрованный бэкап ключей."""
    backup = db.query(KeyBackup).filter(KeyBackup.user_id == user.id).first()
    if not backup:
        raise HTTPException(404, "No backup found")
    return {
        "vault_data": backup.vault_data,
        "vault_salt": backup.vault_salt,
        "kdf_params": backup.kdf_params,
        "version": backup.version,
        "updated_at": backup.updated_at.isoformat() if backup.updated_at else None,
    }


@router.delete("/backup")
async def delete_backup(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Удалить бэкап ключей."""
    deleted = db.query(KeyBackup).filter(KeyBackup.user_id == user.id).delete()
    db.commit()
    if not deleted:
        raise HTTPException(404, "No backup found")
    return {"ok": True, "message": "Backup deleted"}


# ══════════════════════════════════════════════════════════════════════════════
# Device Linking
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/link/request")
async def create_link_request(
    body: LinkRequestCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Новое устройство запрашивает связывание. Возвращает 6-значный код.
    Код действует 10 минут. Пользователь вводит его на старом устройстве.
    """
    try:
        pub_bytes = bytes.fromhex(body.new_device_pub)
        if len(pub_bytes) != 32:
            raise ValueError
    except ValueError:
        raise HTTPException(400, "new_device_pub must be 64 hex chars (32 bytes)")

    # Expire old pending requests for this user
    now = datetime.now(timezone.utc)
    db.query(DeviceLinkRequest).filter(
        DeviceLinkRequest.user_id == user.id,
        DeviceLinkRequest.status == "pending",
    ).update({"status": "expired"})

    # Generate 6-digit code
    link_code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hash_token(link_code)

    req = DeviceLinkRequest(
        user_id=user.id,
        link_code_hash=code_hash,
        new_device_pub=body.new_device_pub,
        status="pending",
        expires_at=now + timedelta(minutes=_LINK_CODE_TTL_MIN),
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    return {
        "request_id": req.id,
        "link_code": link_code,
        "expires_in_seconds": _LINK_CODE_TTL_MIN * 60,
    }


@router.get("/link/{code}")
async def get_link_request(
    code: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Старое устройство проверяет запрос по коду.
    Возвращает X25519 pub нового устройства для ECIES шифрования.
    """
    now = datetime.now(timezone.utc)
    # Find matching pending request for this user
    pending = db.query(DeviceLinkRequest).filter(
        DeviceLinkRequest.user_id == user.id,
        DeviceLinkRequest.status == "pending",
        DeviceLinkRequest.expires_at > now,
    ).all()

    for req in pending:
        if verify_token_hash(code, req.link_code_hash):
            return {
                "request_id": req.id,
                "new_device_pub": req.new_device_pub,
                "created_at": req.created_at.isoformat() if req.created_at else None,
            }

    raise HTTPException(404, "Invalid or expired link code")


@router.post("/link/{code}/approve")
async def approve_link_request(
    code: str,
    body: LinkApproveRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Старое устройство одобряет запрос и отправляет зашифрованные ключи.
    encrypted_keys — ECIES(new_device_pub, key_bundle) в hex.
    """
    try:
        bytes.fromhex(body.encrypted_keys)
    except ValueError:
        raise HTTPException(400, "encrypted_keys must be valid hex")

    now = datetime.now(timezone.utc)
    pending = db.query(DeviceLinkRequest).filter(
        DeviceLinkRequest.user_id == user.id,
        DeviceLinkRequest.status == "pending",
        DeviceLinkRequest.expires_at > now,
    ).all()

    for req in pending:
        if verify_token_hash(code, req.link_code_hash):
            req.encrypted_keys = body.encrypted_keys
            req.status = "approved"
            db.commit()
            return {"ok": True, "message": "Keys transferred"}

    raise HTTPException(404, "Invalid or expired link code")


@router.get("/link/poll/{request_id}")
async def poll_link_request(
    request_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Новое устройство проверяет статус запроса.
    Когда status=approved, encrypted_keys содержит зашифрованный ключевой бандл.
    """
    req = db.query(DeviceLinkRequest).filter(
        DeviceLinkRequest.id == request_id,
        DeviceLinkRequest.user_id == user.id,
    ).first()

    if not req:
        raise HTTPException(404, "Link request not found")

    now = datetime.now(timezone.utc)
    expires = req.expires_at.replace(tzinfo=timezone.utc) if req.expires_at and req.expires_at.tzinfo is None else req.expires_at
    if expires and expires < now and req.status == "pending":
        req.status = "expired"
        db.commit()

    result = {"status": req.status}
    if req.status == "approved" and req.encrypted_keys:
        result["encrypted_keys"] = req.encrypted_keys
        # One-time read: delete after retrieval
        req.status = "completed"
        req.encrypted_keys = None
        db.commit()

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Auto-Sync: encrypted key/history events between devices
# ══════════════════════════════════════════════════════════════════════════════
# Server is a dumb relay — it stores opaque encrypted blobs and cannot
# distinguish key material from random noise. All encryption/decryption
# happens client-side using a sync key derived from the user's master key.

_MAX_SYNC_EVENTS = 500  # max stored per user (FIFO)


class SyncPushRequest(BaseModel):
    device_id: int
    event_type: str = Field(..., pattern=r"^(key_update|history)$")
    payload: str = Field(..., min_length=24, description="hex: encrypted blob")


class CrossSignRequest(BaseModel):
    signer_device: int
    signed_device: int
    signature: str = Field(..., min_length=64, description="hex: HMAC-SHA256")
    signer_pub_hash: str = Field(..., min_length=64, max_length=64)
    signed_pub_hash: str = Field(..., min_length=64, max_length=64)


class ShareCreateItem(BaseModel):
    share_index: int = Field(..., ge=1, le=255)
    encrypted_share: str = Field(..., min_length=24, description="ECIES-encrypted share (hex)")
    recipient_id: int | None = None
    label: str | None = Field(None, max_length=100)


class SSSSCreateRequest(BaseModel):
    threshold: int = Field(..., ge=2, le=255, description="M — minimum shares to reconstruct")
    total_shares: int = Field(..., ge=2, le=255, description="N — total shares")
    shares: list[ShareCreateItem] = Field(..., min_length=2)


class DevicePubKeyRequest(BaseModel):
    device_pub_key: str = Field(..., min_length=64, max_length=64, description="X25519 pub hex (32 bytes)")


class FederatedShardItem(BaseModel):
    shard_index: int = Field(..., ge=1, le=255)
    peer_ip: str = Field(..., min_length=1)
    peer_port: int = Field(..., ge=1, le=65535)
    encrypted_shard: str = Field(..., min_length=24, description="ECIES-encrypted shard (hex)")
    shard_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 of plaintext shard")


class FederatedBackupRequest(BaseModel):
    threshold: int = Field(..., ge=2, le=255)
    total_shards: int = Field(..., ge=2, le=255)
    shards: list[FederatedShardItem] = Field(..., min_length=2)


class StoreShardRequest(BaseModel):
    owner_user_id: int
    shard_index: int = Field(..., ge=1)
    encrypted_shard: str = Field(..., min_length=24)
    shard_hash: str = Field(..., min_length=64, max_length=64)


class KTLogRequest(BaseModel):
    key_type: str = Field(..., pattern=r"^(x25519|kyber|device)$")
    pub_key_hash: str = Field(..., min_length=64, max_length=64)
    device_id: int | None = None


@router.post("/sync/push")
async def sync_push(
    body: SyncPushRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Push encrypted sync event. Server sees only opaque hex blob.
    Client encrypts with sync_key = HKDF(master_key, info="vortex-sync").
    """
    try:
        bytes.fromhex(body.payload)
    except ValueError:
        raise HTTPException(400, "payload must be valid hex")

    # Monotonic sequence number per user
    max_seq = db.query(SyncEvent.seq).filter(
        SyncEvent.user_id == user.id,
    ).order_by(SyncEvent.seq.desc()).first()
    next_seq = (max_seq[0] + 1) if max_seq else 1

    evt = SyncEvent(
        user_id=user.id,
        device_id=body.device_id,
        event_type=body.event_type,
        payload=body.payload,
        seq=next_seq,
    )
    db.add(evt)

    # FIFO: keep only latest N events per user
    count = db.query(SyncEvent).filter(SyncEvent.user_id == user.id).count()
    if count > _MAX_SYNC_EVENTS:
        oldest = db.query(SyncEvent).filter(
            SyncEvent.user_id == user.id,
        ).order_by(SyncEvent.seq.asc()).limit(count - _MAX_SYNC_EVENTS).all()
        for o in oldest:
            db.delete(o)

    db.commit()
    return {"ok": True, "seq": next_seq}


@router.get("/sync/pull")
async def sync_pull(
    since_seq: int = 0,
    event_type: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Pull encrypted sync events since given sequence number.
    Client decrypts each payload locally.
    """
    q = db.query(SyncEvent).filter(
        SyncEvent.user_id == user.id,
        SyncEvent.seq > since_seq,
    )
    if event_type:
        q = q.filter(SyncEvent.event_type == event_type)
    events = q.order_by(SyncEvent.seq.asc()).limit(100).all()
    return {
        "events": [
            {
                "seq": e.seq,
                "device_id": e.device_id,
                "event_type": e.event_type,
                "payload": e.payload,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
    }


@router.get("/sync/history-export/{room_id}")
async def sync_history_export(
    room_id: int,
    limit: int = 200,
    before_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Export encrypted messages from a room for cross-device history migration.
    Returns raw ciphertext blobs — client decrypts with room key.
    Only members can export.
    """
    from app.models_rooms import Message, RoomMember

    membership = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
    ).first()
    if not membership:
        raise HTTPException(403, "Not a member of this room")

    limit = min(limit, 500)
    q = db.query(Message).filter(
        Message.room_id == room_id,
        Message.is_scheduled.is_(False),
    )
    if before_id:
        q = q.filter(Message.id < before_id)
    messages = q.order_by(Message.id.desc()).limit(limit).all()

    return {
        "room_id": room_id,
        "messages": [
            {
                "id": m.id,
                "sender_id": m.sender_id,
                "sender_pseudo": m.sender_pseudo,
                "ciphertext": m.content_encrypted.hex() if m.content_encrypted else None,
                "msg_type": m.msg_type.value if m.msg_type else "text",
                "reply_to_id": m.reply_to_id,
                "created_at": m.created_at.isoformat() if m.created_at else None,
                "is_edited": m.is_edited or False,
            }
            for m in reversed(messages)
        ],
        "has_more": len(messages) == limit,
    }


@router.get("/sync/rooms-summary")
async def sync_rooms_summary(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List rooms the user is a member of, with message counts.
    Used by new devices to know which rooms to migrate.
    """
    from app.models_rooms import Message, Room, RoomMember
    from sqlalchemy import func

    memberships = (
        db.query(
            RoomMember.room_id,
            Room.name,
            Room.is_dm,
            Room.is_channel,
            func.count(Message.id).label("msg_count"),
        )
        .join(Room, Room.id == RoomMember.room_id)
        .outerjoin(Message, Message.room_id == RoomMember.room_id)
        .filter(RoomMember.user_id == user.id)
        .group_by(RoomMember.room_id, Room.name, Room.is_dm, Room.is_channel)
        .all()
    )
    return {
        "rooms": [
            {
                "room_id": m.room_id,
                "name": m.name,
                "is_dm": m.is_dm,
                "is_channel": m.is_channel,
                "msg_count": m.msg_count,
            }
            for m in memberships
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Cross-Signing: mutual device verification
# ══════════════════════════════════════════════════════════════════════════════
# Each device signs other devices' public keys using HMAC-SHA256 with a
# key derived from the user's master secret. The server stores only the
# signature and pub hashes — it cannot forge signatures without the master key.

@router.post("/cross-sign")
async def cross_sign(
    body: CrossSignRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Register a cross-signing record (device A vouches for device B)."""
    try:
        bytes.fromhex(body.signature)
        bytes.fromhex(body.signer_pub_hash)
        bytes.fromhex(body.signed_pub_hash)
    except ValueError:
        raise HTTPException(400, "Fields must be valid hex")

    # Prevent duplicate
    existing = db.query(DeviceCrossSign).filter(
        DeviceCrossSign.user_id == user.id,
        DeviceCrossSign.signer_device == body.signer_device,
        DeviceCrossSign.signed_device == body.signed_device,
    ).first()
    if existing:
        existing.signature = body.signature
        existing.signer_pub_hash = body.signer_pub_hash
        existing.signed_pub_hash = body.signed_pub_hash
        existing.created_at = datetime.now(timezone.utc)
    else:
        cs = DeviceCrossSign(
            user_id=user.id,
            signer_device=body.signer_device,
            signed_device=body.signed_device,
            signature=body.signature,
            signer_pub_hash=body.signer_pub_hash,
            signed_pub_hash=body.signed_pub_hash,
        )
        db.add(cs)
    db.commit()
    return {"ok": True}


@router.get("/cross-sign")
async def get_cross_signs(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all cross-signing records for this user's devices."""
    signs = db.query(DeviceCrossSign).filter(
        DeviceCrossSign.user_id == user.id,
    ).all()
    return {
        "signs": [
            {
                "signer_device": s.signer_device,
                "signed_device": s.signed_device,
                "signature": s.signature,
                "signer_pub_hash": s.signer_pub_hash,
                "signed_pub_hash": s.signed_pub_hash,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in signs
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Sync Preferences (stored client-side, but server holds encrypted copy)
# ══════════════════════════════════════════════════════════════════════════════
# Preferences are stored as an encrypted blob — server cannot read them.
# This allows restoring preferences on new devices.

@router.post("/sync/settings")
async def save_sync_settings(
    body: BackupUploadRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Save encrypted sync preferences (auto_key_sync, history_sync flags, etc)."""
    try:
        bytes.fromhex(body.vault_data)
        bytes.fromhex(body.vault_salt)
    except ValueError:
        raise HTTPException(400, "Fields must be valid hex")

    # Store as a special SyncEvent with seq=0 (settings marker)
    existing = db.query(SyncEvent).filter(
        SyncEvent.user_id == user.id,
        SyncEvent.event_type == "settings",
    ).first()
    if existing:
        existing.payload = body.vault_data
        existing.created_at = datetime.now(timezone.utc)
    else:
        evt = SyncEvent(
            user_id=user.id,
            device_id=0,
            event_type="settings",
            payload=body.vault_data,
            seq=0,
        )
        db.add(evt)
    db.commit()
    return {"ok": True}


@router.get("/sync/settings")
async def get_sync_settings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get encrypted sync preferences."""
    evt = db.query(SyncEvent).filter(
        SyncEvent.user_id == user.id,
        SyncEvent.event_type == "settings",
    ).first()
    if not evt:
        raise HTTPException(404, "No sync settings found")
    return {"payload": evt.payload}


# ══════════════════════════════════════════════════════════════════════════════
# SSSS — Shamir's Secret Sharing Scheme (M-of-N key recovery)
# ══════════════════════════════════════════════════════════════════════════════
# Client performs all Shamir GF(256) math. Each share is encrypted (ECIES)
# for its designated recipient. Server stores only encrypted blobs.
# To recover: M recipients decrypt their shares → client recombines.

@router.post("/ssss/create")
async def ssss_create(
    body: SSSSCreateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create M-of-N secret sharing. Client splits and encrypts shares."""
    if body.threshold > body.total_shares:
        raise HTTPException(400, "threshold must be <= total_shares")
    if len(body.shares) != body.total_shares:
        raise HTTPException(400, f"Expected {body.total_shares} shares, got {len(body.shares)}")

    for s in body.shares:
        try:
            bytes.fromhex(s.encrypted_share)
        except ValueError:
            raise HTTPException(400, f"Share {s.share_index}: encrypted_share must be valid hex")

    # Revoke any existing shares for this user
    db.query(SecretShare).filter(
        SecretShare.owner_id == user.id,
        SecretShare.status == "active",
    ).update({"status": "revoked"})

    for s in body.shares:
        share = SecretShare(
            owner_id=user.id,
            recipient_id=s.recipient_id,
            share_index=s.share_index,
            encrypted_share=s.encrypted_share,
            threshold=body.threshold,
            total_shares=body.total_shares,
            label=s.label,
        )
        db.add(share)
    db.commit()
    return {"ok": True, "threshold": body.threshold, "total_shares": body.total_shares}


@router.get("/ssss/shares")
async def ssss_list_own(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List my active shares (as key owner)."""
    shares = db.query(SecretShare).filter(
        SecretShare.owner_id == user.id,
        SecretShare.status == "active",
    ).order_by(SecretShare.share_index).all()
    if not shares:
        return {"shares": [], "threshold": 0, "total_shares": 0}
    return {
        "threshold": shares[0].threshold,
        "total_shares": shares[0].total_shares,
        "shares": [
            {
                "id": s.id,
                "share_index": s.share_index,
                "recipient_id": s.recipient_id,
                "label": s.label,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in shares
        ],
    }


@router.get("/ssss/held")
async def ssss_list_held(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List shares I hold for others (as recipient)."""
    shares = db.query(SecretShare).filter(
        SecretShare.recipient_id == user.id,
        SecretShare.status == "active",
    ).all()
    return {
        "shares": [
            {
                "id": s.id,
                "owner_id": s.owner_id,
                "share_index": s.share_index,
                "encrypted_share": s.encrypted_share,
                "threshold": s.threshold,
                "total_shares": s.total_shares,
                "label": s.label,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in shares
        ],
    }


@router.delete("/ssss")
async def ssss_revoke(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke all active shares for this user."""
    count = db.query(SecretShare).filter(
        SecretShare.owner_id == user.id,
        SecretShare.status == "active",
    ).update({"status": "revoked"})
    db.commit()
    if not count:
        raise HTTPException(404, "No active shares found")
    return {"ok": True, "revoked": count}


# ══════════════════════════════════════════════════════════════════════════════
# Per-device public key (for fingerprint verification)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/device-pub-key")
async def set_device_pub_key(
    body: DevicePubKeyRequest,
    request: __import__("fastapi").Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Set X25519 public key for current device (per-device fingerprint)."""
    from app.models import UserDevice
    try:
        pub_bytes = bytes.fromhex(body.device_pub_key)
        if len(pub_bytes) != 32:
            raise ValueError
    except ValueError:
        raise HTTPException(400, "device_pub_key must be 64 hex chars (32 bytes)")

    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        raise HTTPException(400, "No refresh token")
    current_hash = hash_token(raw_refresh)
    device = db.query(UserDevice).filter(
        UserDevice.user_id == user.id,
        UserDevice.refresh_token_hash == current_hash,
    ).first()
    if not device:
        raise HTTPException(404, "Current device not found")
    device.device_pub_key = body.device_pub_key
    db.commit()

    # Auto-log to key transparency
    _kt_auto_log(user.id, "device", body.device_pub_key, device.id, db)

    return {"ok": True, "device_id": device.id}


# ══════════════════════════════════════════════════════════════════════════════
# Federated Backup — distribute encrypted shards to federation peers
# ══════════════════════════════════════════════════════════════════════════════
# Client splits backup (Shamir), encrypts each shard (ECIES) for the peer's
# node X25519 pubkey, and uploads metadata. Shards are forwarded to peers via
# HTTP POST. For recovery: pull shards from peers.

async def _push_shard_to_peer(owner_user_id: int, shard) -> bool:
    """Best-effort push of a single shard to a federation peer."""
    try:
        scheme = "https" if getattr(
            __import__("app.config", fromlist=["Config"]).Config, "SSL_ENABLED", False
        ) else "http"
        url = f"{scheme}://{shard.peer_ip}:{shard.peer_port}/api/keys/federated-backup/store-shard"
        async with httpx.AsyncClient(verify=_peer_ssl_ctx, timeout=10.0) as client:
            resp = await client.post(url, json={
                "owner_user_id": owner_user_id,
                "shard_index": shard.shard_index,
                "encrypted_shard": shard.encrypted_shard,
                "shard_hash": shard.shard_hash,
            })
            return resp.status_code == 200
    except Exception as e:
        logger.warning("Failed to push shard %d to %s:%d: %s",
                       shard.shard_index, shard.peer_ip, shard.peer_port, e)
        return False


@router.post("/federated-backup/distribute")
async def federated_backup_distribute(
    body: FederatedBackupRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Distribute encrypted backup shards to federation peers."""
    if body.threshold > body.total_shards:
        raise HTTPException(400, "threshold must be <= total_shards")
    if len(body.shards) != body.total_shards:
        raise HTTPException(400, f"Expected {body.total_shards} shards, got {len(body.shards)}")

    for s in body.shards:
        try:
            bytes.fromhex(s.encrypted_shard)
            bytes.fromhex(s.shard_hash)
        except ValueError:
            raise HTTPException(400, f"Shard {s.shard_index}: invalid hex")

    # Revoke old shards
    db.query(FederatedBackupShard).filter(
        FederatedBackupShard.user_id == user.id,
    ).delete()

    for s in body.shards:
        shard = FederatedBackupShard(
            user_id=user.id,
            shard_index=s.shard_index,
            peer_ip=s.peer_ip,
            peer_port=s.peer_port,
            encrypted_shard=s.encrypted_shard,
            shard_hash=s.shard_hash,
            threshold=body.threshold,
            total_shards=body.total_shards,
        )
        db.add(shard)
    db.commit()

    # Async: push shards to peers (best-effort, non-blocking)
    placed = 0
    for s in body.shards:
        ok = await _push_shard_to_peer(user.id, s)
        if ok:
            placed += 1

    return {"ok": True, "placed": placed, "total": body.total_shards}


@router.get("/federated-backup/status")
async def federated_backup_status(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get status of federated backup shards."""
    shards = db.query(FederatedBackupShard).filter(
        FederatedBackupShard.user_id == user.id,
    ).order_by(FederatedBackupShard.shard_index).all()
    if not shards:
        return {"distributed": False, "shards": []}
    return {
        "distributed": True,
        "threshold": shards[0].threshold,
        "total_shards": shards[0].total_shards,
        "shards": [
            {
                "shard_index": s.shard_index,
                "peer_ip": s.peer_ip,
                "peer_port": s.peer_port,
                "shard_hash": s.shard_hash,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in shards
        ],
    }


@router.post("/federated-backup/store-shard")
async def federated_backup_store_shard(
    body: StoreShardRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Receive and store an encrypted shard from another peer (peer-to-peer, private IPs only)."""
    # Validate peer — only accept from private IPs (peer-to-peer)
    client_ip = request.client.host if request.client else ""
    if not _is_peer_ip(client_ip):
        raise HTTPException(403, "Forbidden: only peer nodes can store shards")
    try:
        bytes.fromhex(body.encrypted_shard)
        bytes.fromhex(body.shard_hash)
    except ValueError:
        raise HTTPException(400, "Fields must be valid hex")

    # Store as a local shard (peer_ip=localhost since we ARE the peer)
    shard = FederatedBackupShard(
        user_id=body.owner_user_id,
        shard_index=body.shard_index,
        peer_ip="localhost",
        peer_port=0,
        encrypted_shard=body.encrypted_shard,
        shard_hash=body.shard_hash,
        threshold=0,
        total_shards=0,
        status="held",
    )
    db.add(shard)
    db.commit()
    return {"ok": True}


@router.get("/federated-backup/retrieve-shard/{owner_user_id}")
async def federated_backup_retrieve_shard(
    owner_user_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Retrieve a shard held for another user (peer-to-peer, private IPs only)."""
    # Validate peer — only accept from private IPs (peer-to-peer)
    client_ip = request.client.host if request.client else ""
    if not _is_peer_ip(client_ip):
        raise HTTPException(403, "Forbidden: only peer nodes can retrieve shards")
    shards = db.query(FederatedBackupShard).filter(
        FederatedBackupShard.user_id == owner_user_id,
        FederatedBackupShard.status == "held",
    ).all()
    if not shards:
        raise HTTPException(404, "No shards held for this user")
    return {
        "shards": [
            {
                "shard_index": s.shard_index,
                "encrypted_shard": s.encrypted_shard,
                "shard_hash": s.shard_hash,
            }
            for s in shards
        ],
    }


@router.delete("/federated-backup")
async def federated_backup_delete(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete all federated backup shards."""
    count = db.query(FederatedBackupShard).filter(
        FederatedBackupShard.user_id == user.id,
    ).delete()
    db.commit()
    if not count:
        raise HTTPException(404, "No federated backup found")
    return {"ok": True, "deleted": count}


# ══════════════════════════════════════════════════════════════════════════════
# Key Transparency Log — append-only verifiable key history
# ══════════════════════════════════════════════════════════════════════════════
# Each entry chains to previous via prev_hash (Merkle-like). Server signs
# each entry with HMAC-SHA256(server_secret, entry_data). Clients verify
# the chain to detect unauthorized key insertions or silent replacements.

_KT_SECRET_KEY = None

def _get_kt_secret():
    """Derive a stable key transparency signing key from the server secret."""
    global _KT_SECRET_KEY
    if _KT_SECRET_KEY is None:
        import hmac
        from app.config import Config
        seed = (Config.JWT_SECRET or "vortex-default-key").encode()
        _KT_SECRET_KEY = hmac.new(seed, b"vortex-key-transparency", "sha256").digest()
    return _KT_SECRET_KEY


def _kt_sign_entry(user_id: int, key_type: str, pub_key_hash: str, prev_hash: str | None, seq: int) -> str:
    """HMAC-SHA256 signature of a KT entry."""
    import hmac as _hmac
    data = f"{user_id}|{key_type}|{pub_key_hash}|{prev_hash or ''}|{seq}".encode()
    return _hmac.new(_get_kt_secret(), data, "sha256").hexdigest()


def _kt_auto_log(user_id: int, key_type: str, pub_key_hex: str, device_id: int | None, db: Session):
    """Auto-log a key change to the transparency log."""
    import hashlib as _hl
    pub_key_hash = _hl.sha256(pub_key_hex.encode()).hexdigest()

    # Get previous entry
    prev = db.query(KeyTransparencyEntry).filter(
        KeyTransparencyEntry.user_id == user_id,
    ).order_by(KeyTransparencyEntry.seq.desc()).first()

    prev_hash = None
    next_seq = 1
    if prev:
        prev_data = f"{prev.user_id}|{prev.key_type}|{prev.pub_key_hash}|{prev.prev_hash or ''}|{prev.seq}"
        prev_hash = _hl.sha256(prev_data.encode()).hexdigest()
        next_seq = prev.seq + 1

    signature = _kt_sign_entry(user_id, key_type, pub_key_hash, prev_hash, next_seq)

    entry = KeyTransparencyEntry(
        user_id=user_id,
        key_type=key_type,
        pub_key_hash=pub_key_hash,
        prev_hash=prev_hash,
        signature=signature,
        device_id=device_id,
        seq=next_seq,
    )
    db.add(entry)
    db.commit()
    return entry


@router.post("/transparency/log")
async def kt_log_key(
    body: KTLogRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manually log a key to the transparency log (client-initiated)."""
    try:
        bytes.fromhex(body.pub_key_hash)
    except ValueError:
        raise HTTPException(400, "pub_key_hash must be valid hex")

    entry = _kt_auto_log(user.id, body.key_type, body.pub_key_hash, body.device_id, db)
    return {"ok": True, "seq": entry.seq}


@router.get("/transparency/{user_id}")
async def kt_get_log(
    user_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get full key transparency log for a user."""
    entries = db.query(KeyTransparencyEntry).filter(
        KeyTransparencyEntry.user_id == user_id,
    ).order_by(KeyTransparencyEntry.seq.asc()).all()
    return {
        "entries": [
            {
                "seq": e.seq,
                "key_type": e.key_type,
                "pub_key_hash": e.pub_key_hash,
                "prev_hash": e.prev_hash,
                "signature": e.signature,
                "device_id": e.device_id,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
        ],
    }


@router.get("/transparency/{user_id}/latest")
async def kt_get_latest(
    user_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get latest key transparency entry for a user."""
    entry = db.query(KeyTransparencyEntry).filter(
        KeyTransparencyEntry.user_id == user_id,
    ).order_by(KeyTransparencyEntry.seq.desc()).first()
    if not entry:
        raise HTTPException(404, "No key transparency entries found")
    return {
        "seq": entry.seq,
        "key_type": entry.key_type,
        "pub_key_hash": entry.pub_key_hash,
        "prev_hash": entry.prev_hash,
        "signature": entry.signature,
        "device_id": entry.device_id,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@router.get("/transparency/{user_id}/audit")
async def kt_audit(
    user_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify the integrity of a user's key transparency chain."""
    import hashlib as _hl
    entries = db.query(KeyTransparencyEntry).filter(
        KeyTransparencyEntry.user_id == user_id,
    ).order_by(KeyTransparencyEntry.seq.asc()).all()

    if not entries:
        return {"valid": True, "entries": 0, "errors": []}

    errors = []
    for i, e in enumerate(entries):
        # Verify signature
        expected_sig = _kt_sign_entry(e.user_id, e.key_type, e.pub_key_hash, e.prev_hash, e.seq)
        if e.signature != expected_sig:
            errors.append({"seq": e.seq, "error": "invalid_signature"})

        # Verify chain (prev_hash)
        if i == 0:
            if e.prev_hash is not None:
                errors.append({"seq": e.seq, "error": "first_entry_has_prev_hash"})
        else:
            prev = entries[i - 1]
            prev_data = f"{prev.user_id}|{prev.key_type}|{prev.pub_key_hash}|{prev.prev_hash or ''}|{prev.seq}"
            expected_prev = _hl.sha256(prev_data.encode()).hexdigest()
            if e.prev_hash != expected_prev:
                errors.append({"seq": e.seq, "error": "broken_chain"})

        # Verify monotonic seq
        if e.seq != i + 1:
            errors.append({"seq": e.seq, "error": f"expected_seq_{i + 1}"})

    return {"valid": len(errors) == 0, "entries": len(entries), "errors": errors}
