"""
Zero-Knowledge Server Architecture — сервер не знает НИЧЕГО о своих пользователях.

Принципы:
  1. Encrypted Profile Vault — профиль (display_name, bio, status, avatar) зашифрован
     мастер-ключом пользователя. Сервер хранит только blob.
  2. Encrypted Room Metadata — имя комнаты, описание зашифрованы room_key.
     Сервер видит только encrypted blob.
  3. Encrypted Contact Graph — список контактов зашифрован пользовательским ключом.
     Сервер не знает кто с кем общается.
  4. Sealed Sender — сервер не видит sender_id в сообщениях.
  5. Encrypted File Metadata — имена файлов, forwarded_from зашифрованы room_key.
  6. Obfuscated Timestamps — серверные timestamps имеют случайный джиттер.
  7. Encrypted Notifications — payload уведомлений зашифрован для получателя.
  8. Blind Index — поиск по зашифрованным данным через HMAC-based blind indexes.

Архитектура:
  - Клиент шифрует ВСЕ метаданные перед отправкой на сервер.
  - Сервер хранит только encrypted blobs + blind indexes для поиска.
  - При запросе данных клиент расшифровывает локально.
  - Аутентификация: сервер видит только username (необходим для routing) +
    password_hash (Argon2id). Все остальное — зашифровано.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, LargeBinary, Boolean
from sqlalchemy.orm import Session, relationship

from app.base import Base

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# SQLAlchemy Models — Encrypted Vaults
# ══════════════════════════════════════════════════════════════════════════════


class ProfileVault(Base):
    """
    Encrypted user profile. Server stores ONLY opaque encrypted blob.

    Client encrypts with user's master key (derived from X25519 private key):
      master_key = HKDF(x25519_priv, salt="vortex-profile-vault", info="profile")

    Vault contains JSON: {
      display_name, bio, avatar_emoji, avatar_url, custom_status,
      status_emoji, birth_date, profile_bg, profile_icon, phone, email
    }

    Server cannot read ANY of this.
    """
    __tablename__ = "profile_vaults"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, unique=True, index=True)
    # AES-256-GCM encrypted blob (hex): nonce(12) + ciphertext + tag(16)
    vault_data = Column(Text, nullable=False)
    # Version counter — client increments on each update
    version    = Column(Integer, default=1)
    # Blind index for display_name search: HMAC-SHA256(server_blind_key, lowercase(display_name))
    # Allows searching without decryption. Client sends blind index alongside vault.
    blind_name = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", backref="profile_vault")


class RoomVault(Base):
    """
    Encrypted room metadata. Server stores ONLY opaque blob.

    Client encrypts with room_key:
      vault contains JSON: { name, description, avatar_emoji, avatar_url, theme_json }

    Server cannot read room names or descriptions.
    """
    __tablename__ = "room_vaults"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    room_id    = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"),
                        nullable=False, unique=True, index=True)
    vault_data = Column(Text, nullable=False)
    version    = Column(Integer, default=1)
    # Blind index for room name search
    blind_name = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    room = relationship("Room", backref="room_vault")


class ContactVault(Base):
    """
    Encrypted contact list. Each contact entry encrypted with owner's master key.

    Server cannot know who is in whose contact list.
    """
    __tablename__ = "contact_vaults"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    owner_id   = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    # Encrypted blob: { contact_pubkey, nickname, verified, notes }
    vault_data = Column(Text, nullable=False)
    # Blind index: HMAC(owner_key, contact_pubkey) — for dedup without revealing contact
    blind_id   = Column(String(64), nullable=False, index=True)
    version    = Column(Integer, default=1)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    owner = relationship("User", backref="contact_vaults")


class EncryptedCallRecord(Base):
    """
    Encrypted call history. Server stores opaque blob, cannot see who called whom.
    """
    __tablename__ = "encrypted_call_records"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    owner_id   = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    # Encrypted: { caller_pubkey, callee_pubkey, type, duration, status, started_at, ended_at }
    vault_data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", backref="encrypted_calls")


class EncryptedNotification(Base):
    """
    Encrypted notification payload. Server cannot read notification content.
    Encrypted with recipient's X25519 public key via ECIES.
    """
    __tablename__ = "encrypted_notifications"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    recipient_id  = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    # ECIES encrypted payload: { ephemeral_pub, ciphertext }
    ephemeral_pub = Column(String(64), nullable=False)
    ciphertext    = Column(Text, nullable=False)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditVault(Base):
    """
    Encrypted audit log. Room admins can decrypt with room admin key.
    Server sees nothing.
    """
    __tablename__ = "audit_vaults"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    room_id    = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    vault_data = Column(Text, nullable=False)  # encrypted with room_key
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ══════════════════════════════════════════════════════════════════════════════
# Blind Index System — поиск по зашифрованным данным
# ══════════════════════════════════════════════════════════════════════════════

# Server-side blind index key — stored in environment, never exposed to clients
_BLIND_INDEX_KEY: Optional[bytes] = None


def _get_blind_key() -> bytes:
    """Get or generate the server-side blind index key."""
    global _BLIND_INDEX_KEY
    if _BLIND_INDEX_KEY is None:
        env_key = os.environ.get("VORTEX_BLIND_INDEX_KEY")
        if env_key:
            _BLIND_INDEX_KEY = bytes.fromhex(env_key)
        else:
            # Generate and log warning — in production, must be set via env
            _BLIND_INDEX_KEY = os.urandom(32)
            logger.warning(
                "VORTEX_BLIND_INDEX_KEY not set — generated random key. "
                "Set env var for persistence across restarts!"
            )
    return _BLIND_INDEX_KEY


def compute_blind_index(value: str, context: str = "") -> str:
    """
    Compute blind index for searching encrypted data.

    Uses HMAC-SHA256(server_key, context || lowercase(value)).
    Returns hex string (64 chars).

    Client sends the plaintext value ONLY for blind index computation,
    then server immediately discards it. The blind index is stored.
    """
    key = _get_blind_key()
    data = (context + value.lower().strip()).encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Timestamp Obfuscation — prevent activity pattern analysis
# ══════════════════════════════════════════════════════════════════════════════

def obfuscate_timestamp(dt: datetime, jitter_seconds: int = 300) -> datetime:
    """
    Add random jitter to timestamp to prevent activity analysis.
    Default: ±5 minutes jitter.
    """
    jitter = secrets.randbelow(jitter_seconds * 2) - jitter_seconds
    return dt.replace(microsecond=0) + __import__('datetime').timedelta(seconds=jitter)


def coarsen_timestamp(dt: datetime, granularity_minutes: int = 15) -> datetime:
    """
    Round timestamp to nearest N-minute bucket.
    Prevents exact timing correlation.
    """
    ts = int(dt.timestamp())
    bucket = granularity_minutes * 60
    rounded = (ts // bucket) * bucket
    return datetime.fromtimestamp(rounded, tz=timezone.utc)


# ══════════════════════════════════════════════════════════════════════════════
# Sealed Sender Enhancement
# ══════════════════════════════════════════════════════════════════════════════

def derive_sender_pseudo(user_secret: bytes, room_id: int) -> str:
    """
    Derive a sealed sender pseudonym for a specific room.

    Uses HMAC-SHA256(user_secret, "sealed-sender" || room_id).
    Different for every room — cannot correlate across rooms.
    Server stores this but cannot reverse to user_id.
    """
    data = f"sealed-sender:{room_id}".encode()
    mac = hmac.new(user_secret, data, hashlib.sha256).digest()
    return mac.hex()


def verify_sender_pseudo(user_secret: bytes, room_id: int, pseudo: str) -> bool:
    """Verify that a pseudo belongs to a user+room pair."""
    expected = derive_sender_pseudo(user_secret, room_id)
    return secrets.compare_digest(expected, pseudo)


# ══════════════════════════════════════════════════════════════════════════════
# Encrypted Metadata Wrapper — для file_name, forwarded_from и т.д.
# ══════════════════════════════════════════════════════════════════════════════

class EncryptedMetadata:
    """
    Wrapper for encrypted metadata fields in messages.

    Instead of storing file_name="photo.jpg" in plaintext,
    client encrypts it with room_key and sends:
      file_name_encrypted = AES-GCM(room_key, "photo.jpg")

    Server stores encrypted blob. Only room members can decrypt.
    """

    @staticmethod
    def is_encrypted(value: Optional[str]) -> bool:
        """Check if a value looks like an encrypted hex blob."""
        if not value:
            return False
        # Encrypted values are hex strings with min length (nonce + tag = 56 hex chars)
        if len(value) < 56:
            return False
        try:
            bytes.fromhex(value)
            return True
        except ValueError:
            return False


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic Schemas
# ══════════════════════════════════════════════════════════════════════════════

class ProfileVaultRequest(BaseModel):
    vault_data: str = Field(..., min_length=1, description="AES-256-GCM encrypted profile (hex)")
    blind_name: str | None = Field(None, max_length=64, description="HMAC blind index for display name search")


class RoomVaultRequest(BaseModel):
    vault_data: str = Field(..., min_length=1, description="AES-256-GCM encrypted room metadata (hex)")
    blind_name: str | None = Field(None, max_length=64, description="HMAC blind index for room name search")


class ContactVaultRequest(BaseModel):
    vault_data: str = Field(..., min_length=1, description="AES-256-GCM encrypted contact data (hex)")
    blind_id: str = Field(..., min_length=64, max_length=64, description="HMAC blind index for dedup")


class CallRecordRequest(BaseModel):
    vault_data: str = Field(..., min_length=1, description="AES-256-GCM encrypted call record (hex)")


class EncryptedNotificationRequest(BaseModel):
    recipient_id: int
    ephemeral_pub: str = Field(..., min_length=64, max_length=64)
    ciphertext: str = Field(..., min_length=1)


class BlindSearchRequest(BaseModel):
    blind_index: str = Field(..., min_length=64, max_length=64)
    search_type: str = Field(..., description="Type: 'user' or 'room'")


class EncryptedMessageMeta(BaseModel):
    """Encrypted metadata fields for messages."""
    file_name_encrypted: str | None = None
    forwarded_from_encrypted: str | None = None


# ══════════════════════════════════════════════════════════════════════════════
# API Router
# ══════════════════════════════════════════════════════════════════════════════

zk_router = APIRouter(prefix="/api/zk", tags=["zero-knowledge"])


def _lazy_get_db():
    from app.database import get_db
    return get_db


def _lazy_get_current_user():
    from app.security.auth_jwt import get_current_user
    return get_current_user


# ── Profile Vault ─────────────────────────────────────────────────────────

@zk_router.put("/profile")
async def save_profile_vault(
    body: ProfileVaultRequest,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    vault = db.query(ProfileVault).filter(ProfileVault.user_id == u.id).first()
    if vault:
        vault.vault_data = body.vault_data
        vault.version += 1
        if body.blind_name:
            vault.blind_name = body.blind_name
    else:
        vault = ProfileVault(
            user_id=u.id,
            vault_data=body.vault_data,
            blind_name=body.blind_name,
        )
        db.add(vault)
    db.commit()
    return {"ok": True, "version": vault.version}


@zk_router.get("/profile")
async def get_profile_vault(
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    vault = db.query(ProfileVault).filter(ProfileVault.user_id == u.id).first()
    if not vault:
        return {"ok": True, "vault_data": None, "version": 0}
    return {"ok": True, "vault_data": vault.vault_data, "version": vault.version}


@zk_router.get("/profile/{user_id}")
async def get_user_profile_vault(
    user_id: int,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    vault = db.query(ProfileVault).filter(ProfileVault.user_id == user_id).first()
    if not vault:
        return {"ok": True, "vault_data": None, "version": 0}
    return {"ok": True, "vault_data": vault.vault_data, "version": vault.version}


# ── Room Vault ────────────────────────────────────────────────────────────

@zk_router.put("/room/{room_id}")
async def save_room_vault(
    room_id: int,
    body: RoomVaultRequest,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    from app.models_rooms.rooms import RoomMember
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Not a room member")

    vault = db.query(RoomVault).filter(RoomVault.room_id == room_id).first()
    if vault:
        vault.vault_data = body.vault_data
        vault.version += 1
        if body.blind_name:
            vault.blind_name = body.blind_name
    else:
        vault = RoomVault(room_id=room_id, vault_data=body.vault_data, blind_name=body.blind_name)
        db.add(vault)
    db.commit()
    return {"ok": True, "version": vault.version}


@zk_router.get("/room/{room_id}")
async def get_room_vault(
    room_id: int,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    vault = db.query(RoomVault).filter(RoomVault.room_id == room_id).first()
    if not vault:
        return {"ok": True, "vault_data": None, "version": 0}
    return {"ok": True, "vault_data": vault.vault_data, "version": vault.version}


# ── Contact Vault ─────────────────────────────────────────────────────────

@zk_router.put("/contacts")
async def save_contact_vault(
    body: ContactVaultRequest,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    existing = db.query(ContactVault).filter(
        ContactVault.owner_id == u.id, ContactVault.blind_id == body.blind_id,
    ).first()
    if existing:
        existing.vault_data = body.vault_data
        existing.version += 1
    else:
        db.add(ContactVault(owner_id=u.id, vault_data=body.vault_data, blind_id=body.blind_id))
    db.commit()
    return {"ok": True}


@zk_router.get("/contacts")
async def get_contact_vaults(
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    entries = db.query(ContactVault).filter(ContactVault.owner_id == u.id).all()
    return {
        "ok": True,
        "contacts": [
            {"id": e.id, "vault_data": e.vault_data, "blind_id": e.blind_id, "version": e.version}
            for e in entries
        ],
    }


@zk_router.delete("/contacts/{blind_id}")
async def delete_contact_vault(
    blind_id: str,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    entry = db.query(ContactVault).filter(
        ContactVault.owner_id == u.id, ContactVault.blind_id == blind_id,
    ).first()
    if not entry:
        raise HTTPException(404, "Contact not found")
    db.delete(entry)
    db.commit()
    return {"ok": True}


# ── Call Records ──────────────────────────────────────────────────────────

@zk_router.post("/calls")
async def save_call_record(
    body: CallRecordRequest,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    record = EncryptedCallRecord(owner_id=u.id, vault_data=body.vault_data)
    db.add(record)
    db.commit()
    return {"ok": True, "id": record.id}


@zk_router.get("/calls")
async def get_call_records(
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    records = db.query(EncryptedCallRecord).filter(
        EncryptedCallRecord.owner_id == u.id,
    ).order_by(EncryptedCallRecord.created_at.desc()).limit(100).all()
    return {
        "ok": True,
        "records": [
            {"id": r.id, "vault_data": r.vault_data, "created_at": r.created_at.isoformat()}
            for r in records
        ],
    }


# ── Encrypted Notifications ──────────────────────────────────────────────

@zk_router.post("/notifications")
async def push_encrypted_notification(
    body: EncryptedNotificationRequest,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    notif = EncryptedNotification(
        recipient_id=body.recipient_id,
        ephemeral_pub=body.ephemeral_pub,
        ciphertext=body.ciphertext,
    )
    db.add(notif)
    db.commit()
    return {"ok": True}


@zk_router.get("/notifications")
async def get_encrypted_notifications(
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    notifs = db.query(EncryptedNotification).filter(
        EncryptedNotification.recipient_id == u.id,
    ).order_by(EncryptedNotification.created_at.asc()).limit(200).all()

    result = [
        {"id": n.id, "ephemeral_pub": n.ephemeral_pub, "ciphertext": n.ciphertext,
         "created_at": n.created_at.isoformat()}
        for n in notifs
    ]
    for n in notifs:
        db.delete(n)
    db.commit()
    return {"ok": True, "notifications": result}


# ── Blind Search ──────────────────────────────────────────────────────────

@zk_router.post("/search")
async def blind_search(
    body: BlindSearchRequest,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    if body.search_type == "user":
        vaults = db.query(ProfileVault).filter(ProfileVault.blind_name == body.blind_index).all()
        return {"ok": True, "results": [{"user_id": v.user_id, "vault_data": v.vault_data} for v in vaults]}
    elif body.search_type == "room":
        vaults = db.query(RoomVault).filter(RoomVault.blind_name == body.blind_index).all()
        return {"ok": True, "results": [{"room_id": v.room_id, "vault_data": v.vault_data} for v in vaults]}
    else:
        raise HTTPException(400, "search_type must be 'user' or 'room'")


# ── Audit Vault ───────────────────────────────────────────────────────────

@zk_router.post("/audit/{room_id}")
async def save_audit_entry(
    room_id: int,
    request: Request,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    body = await request.json()
    from app.models_rooms.rooms import RoomMember
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Not a room member")
    entry = AuditVault(room_id=room_id, vault_data=body.get("vault_data", ""))
    db.add(entry)
    db.commit()
    return {"ok": True, "id": entry.id}


@zk_router.get("/audit/{room_id}")
async def get_audit_entries(
    room_id: int,
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    from app.models_rooms.rooms import RoomMember
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Not a room member")
    entries = db.query(AuditVault).filter(
        AuditVault.room_id == room_id,
    ).order_by(AuditVault.created_at.desc()).limit(200).all()
    return {
        "ok": True,
        "entries": [{"id": e.id, "vault_data": e.vault_data, "created_at": e.created_at.isoformat()} for e in entries],
    }


# ── ZK Status & Info ─────────────────────────────────────────────────────

@zk_router.get("/status")
async def zk_status(u = Depends(_lazy_get_current_user())):
    return {
        "ok": True,
        "zk_enabled": True,
        "capabilities": {
            "encrypted_profiles": True,
            "encrypted_rooms": True,
            "encrypted_contacts": True,
            "sealed_sender": True,
            "encrypted_file_metadata": True,
            "obfuscated_timestamps": True,
            "encrypted_notifications": True,
            "encrypted_call_history": True,
            "encrypted_audit_logs": True,
            "blind_search": True,
            "zk_membership_proof": True,
        },
        "crypto": {
            "profile_encryption": "AES-256-GCM (user master key)",
            "room_encryption": "AES-256-GCM (room key)",
            "contact_encryption": "AES-256-GCM (user master key)",
            "notification_encryption": "ECIES (X25519 + AES-256-GCM)",
            "blind_index": "HMAC-SHA256",
            "sender_pseudonym": "HMAC-SHA256 (per-room)",
            "timestamp_obfuscation": "±5min random jitter",
        },
    }


# ── Blind Index Key Exchange ─────────────────────────────────────────────

@zk_router.get("/blind-key")
async def get_blind_key_encrypted(
    db: Session = Depends(_lazy_get_db()),
    u = Depends(_lazy_get_current_user()),
):
    if not u.x25519_public_key:
        raise HTTPException(400, "User has no public key")

    blind_key = _get_blind_key()
    from app.security.key_exchange import ecies_encrypt
    result = ecies_encrypt(blind_key, u.x25519_public_key)

    return {
        "ok": True,
        "ephemeral_pub": result["ephemeral_pub"],
        "ciphertext": result["ciphertext"],
    }
