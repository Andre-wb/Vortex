"""
app/models/prekeys.py — Модели для хранения Pre-Key Bundle (X3DH / Double Ratchet).

Таблицы:
  prekey_bundles  — Identity Key + Signed Pre-Key пользователя (одна запись на user).
  onetime_prekeys — Одноразовые Pre-Keys (пачка на пользователя, каждый используется один раз).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
)
from sqlalchemy.orm import relationship

from app.base import Base


class PreKeyBundle(Base):
    """Хранит Identity Key и Signed Pre-Key пользователя.

    Каждый пользователь публикует один набор (identity_key, signed_prekey)
    и периодически ротирует signed_prekey. Identity Key фиксирован на время
    жизни аккаунта (или устройства).

    Attributes:
        user_id:           ID пользователя (FK → users.id).
        identity_key:      32 байта — X25519 публичный Identity Key.
        signed_prekey:     32 байта — X25519 публичный Signed Pre-Key.
        signed_prekey_sig: 64 байта — Ed25519 подпись signed_prekey ключом identity_key.
        signed_prekey_id:  идентификатор SPK для ротации.
        created_at:        время публикации.
        updated_at:        время последнего обновления SPK.
    """
    __tablename__ = "prekey_bundles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    identity_key = Column(LargeBinary(32), nullable=False)
    signed_prekey = Column(LargeBinary(32), nullable=False)
    signed_prekey_sig = Column(LargeBinary(64), nullable=False)
    signed_prekey_id = Column(Integer, nullable=False, default=0)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<PreKeyBundle user_id={self.user_id} "
            f"spk_id={self.signed_prekey_id}>"
        )


class OneTimePreKey(Base):
    """Одноразовый Pre-Key для X3DH.

    Пользователь публикует пачку одноразовых ключей. При запросе Pre-Key Bundle
    один OPK выдаётся и помечается как использованный (used=True).
    Клиент должен пополнять пул при снижении количества доступных OPK.

    Attributes:
        user_id:    ID пользователя (FK → users.id).
        key_id:     локальный идентификатор OPK (назначается клиентом).
        public_key: 32 байта — X25519 публичный ключ.
        used:       True после выдачи в составе Pre-Key Bundle.
        created_at: время публикации.
    """
    __tablename__ = "onetime_prekeys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key_id = Column(Integer, nullable=False)
    public_key = Column(LargeBinary(32), nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<OneTimePreKey user_id={self.user_id} "
            f"key_id={self.key_id} used={self.used}>"
        )
