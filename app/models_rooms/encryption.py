from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.base import Base


class EncryptedRoomKey(Base):
    """
    Ключ комнаты, зашифрованный ECIES для конкретного участника.

    Содержимое (схема ECIES):
      ephemeral_pub -- X25519 публичный ключ эфемерной пары (32 bytes -> 64 hex chars)
      ciphertext    -- nonce(12) + AES-GCM(room_key(32), shared_key) + tag(16)
                      = 60 bytes -> 120 hex chars

    Как это работает:
      shared_key = HKDF( DH(ephemeral_priv, user_pub) )
      ciphertext = AES-256-GCM(room_key, shared_key)

    Сервер не может расшифровать это:
      - ему нужен user_priv (приватный ключ пользователя)
      - который никогда не покидает устройство пользователя

    Клиент расшифровывает:
      shared_key = HKDF( DH(user_priv, ephemeral_pub) )   <- тот же shared_key
      room_key   = AES-256-GCM-decrypt(ciphertext, shared_key)
    """

    __tablename__ = "encrypted_room_keys"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # ECIES поля — то что нужно клиенту для расшифровки
    ephemeral_pub = Column(String(64), nullable=False)  # hex(32 bytes) — X25519 эфемерный pub
    ciphertext = Column(String(120), nullable=False)  # hex(60 bytes) — тот же размер и в гибриде
    # Post-quantum гибрид (X25519 + ML-KEM-768): наличие kyber_ciphertext ⟹ конверт
    # гибридный (клиент разворачивает hybridEciesDecrypt); NULL ⟹ классический ECIES.
    kyber_ciphertext = Column(Text, nullable=True)  # ML-KEM-768 ciphertext hex (1088 байт)

    # Для верификации: ключ зашифрован именно для этого pubkey
    recipient_pub = Column(String(64), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    room = relationship("Room", back_populates="enc_keys")

    __table_args__ = (
        UniqueConstraint("room_id", "user_id"),
        Index("ix_erk_room_user", "room_id", "user_id"),
    )

    def to_client_dict(self) -> dict:
        """Формат для отправки клиенту через WebSocket."""
        if self.kyber_ciphertext:
            return {
                "hybrid": True,
                "x25519_ephemeral_pub": self.ephemeral_pub,
                "kyber_ciphertext": self.kyber_ciphertext,
                "ciphertext": self.ciphertext,
            }
        return {
            "ephemeral_pub": self.ephemeral_pub,
            "ciphertext": self.ciphertext,
        }


class RoomInvite(Base):
    """Личность invite-ссылки для offline-join (ADR-005 O5a — split из O4).

    ПЕРСИСТИТ через ротацию room key (в отличие от обёртки-escrow, которую ротация
    удаляет). Хранит публичные invite-ключи (X25519[+ML-KEM]) — чтобы ЛЮБОЙ онлайн-
    член после ротации мог re-wrap room key для этих pub (не только создатель).
    Приватные invite-ключи — только во фрагменте ссылки (сервер не видит).
    """

    __tablename__ = "room_invites"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False, index=True)
    invite_pub = Column(String(64), nullable=False)  # X25519 invite pub — идентификатор
    invite_kyber_pub = Column(Text, nullable=True)  # ML-KEM invite pub (PQ — персистит, иначе ротация роняет PQ)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    # TTL (ADR-005 O7): истёкший инвайт read-time трактуется как отсутствующий
    # (fetch → has_escrow=false; list исключает → re-wrap не ре-армит). NULL = без TTL.
    expires_at = Column(DateTime, nullable=True, index=True)

    __table_args__ = (
        UniqueConstraint("room_id", "invite_pub"),
        Index("ix_ri_room_invite", "room_id", "invite_pub"),
    )


class RoomInviteEscrow(Base):
    """Room key, обёрнутый на invite-pub (ADR-005 O4/O5a). Идентичность инвайта —
    в `RoomInvite` (персистит); ЗДЕСЬ только обёртка, которую ротация УДАЛЯЕТ (escrow
    на старый ключ → мёртв). После ротации онлайн-член re-wrap'ает по persisted
    `RoomInvite.invite_pub`. **Double-gate:** FETCH гейтится членством
    (_require_member), фрагмент-priv гейтит DECRYPT.
    """

    __tablename__ = "room_invite_escrows"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False, index=True)
    invite_pub = Column(String(64), nullable=False)  # ссылается на RoomInvite.invite_pub
    ephemeral_pub = Column(String(64), nullable=False)
    ciphertext = Column(String(120), nullable=False)
    kyber_ciphertext = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("room_id", "invite_pub"),
        Index("ix_rie_room_invite", "room_id", "invite_pub"),
    )

    def to_client_dict(self) -> dict:
        """Форма конверта для клиента (гибрид/классика по наличию kyber_ciphertext)."""
        if self.kyber_ciphertext:
            return {
                "hybrid": True,
                "x25519_ephemeral_pub": self.ephemeral_pub,
                "kyber_ciphertext": self.kyber_ciphertext,
                "ciphertext": self.ciphertext,
            }
        return {"ephemeral_pub": self.ephemeral_pub, "ciphertext": self.ciphertext}


class PendingKeyRequest(Base):
    """
    Ожидающий запрос на получение ключа комнаты.

    Создаётся когда:
      - Новый участник подключается через WebSocket
      - У него нет записи в EncryptedRoomKey
      - Ни один владелец ключа не онлайн

    Протокол доставки:
      1. User X joins room -> PendingKeyRequest(room_id=R, user_id=X, pubkey=X.pubkey)
      2. Сервер рассылает online-членам: {type: "key_request", for_user_id: X, for_pubkey: "..."}
      3. Любой online-член Y выполняет ECIES(room_key, X.pubkey) на своём клиенте
      4. Y отправляет: {action: "key_response", for_user_id: X, ephemeral_pub: "...", ciphertext: "..."}
      5. Сервер сохраняет EncryptedRoomKey для X, удаляет PendingKeyRequest, доставляет X
      6. Если никто не онлайн: запрос висит до expires_at, очищается через cron/фоновую задачу

    TTL: 48 часов. Если X так и не получил ключ -- при следующем подключении
    PendingKeyRequest создаётся заново.
    """

    __tablename__ = "pending_key_requests"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    pubkey_hex = Column(String(64), nullable=False)  # X25519 pubkey ожидающего (64 hex chars)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc) + timedelta(hours=48))

    room = relationship("Room", back_populates="pending_keys")

    __table_args__ = (
        UniqueConstraint("room_id", "user_id"),
        Index("ix_pkr_room_user", "room_id", "user_id"),
    )

    @property
    def is_expired(self) -> bool:
        # SQLite отдаёт DateTime без tzinfo — считаем такие значения UTC, иначе
        # сравнение aware-now с naive-expires_at падает (offset-naive vs aware).
        exp = self.expires_at
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp


class SealedKeyPackage(Base):
    """
    Pre-seeded encrypted room key package for offline key distribution.

    Created by room creator/admin when room is created or key rotated.
    Each package encrypts the room key for a one-time X25519 pubkey.
    New member generates ephemeral keypair, uploads pubkey, server matches
    with a prekey package encrypted for that pubkey.

    Zero metadata: server stores only (room_id, anon_slot, encrypted_blob).
    No user_id — package is claimed by whoever presents matching pubkey.

    Flow:
      1. Creator generates N prekey packages: ECIES(room_key, prekey_pub_i)
      2. Stored on server as sealed blobs
      3. New member joins → picks unclaimed slot → server returns blob
      4. Member decrypts with their private key → gets room_key
      5. Slot marked as claimed (deleted)

    When all prekeys exhausted → any online member can generate more.
    """

    __tablename__ = "sealed_key_packages"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False, index=True)
    slot_index = Column(Integer, nullable=False)  # 0..N-1
    ephemeral_pub = Column(String(64), nullable=False)  # ECIES ephemeral pub (hex)
    ciphertext = Column(String(120), nullable=False)  # ECIES encrypted room key (hex)
    recipient_pub = Column(String(64), nullable=False)  # one-time pubkey this is encrypted for
    is_claimed = Column(Integer, default=0)  # 0=available, 1=claimed
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (Index("ix_skp_room_avail", "room_id", "is_claimed"),)


class PendingNotification(Base):
    """
    Persistent queue for notifications that couldn't be delivered via WebSocket.

    Stores encrypted payloads (JSON-serialized) for offline users.
    Flushed when user reconnects to /ws/notifications.
    Server cannot read the actual message content (messages are E2E encrypted).
    Only notification metadata (type, room_id, sender info) is stored — no plaintext.
    """

    __tablename__ = "pending_notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    payload = Column(Text, nullable=False)  # JSON-serialized notification
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (Index("ix_pending_notif_user", "user_id", "created_at"),)
