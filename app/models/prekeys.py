"""
app/models/prekeys.py — Модели для хранения Pre-Key Bundle (X3DH / Double Ratchet).

Таблицы:
  prekey_bundles  — Identity Key + Signed Pre-Key (одна запись на устройство: (user_id, device_id)).
  onetime_prekeys — Одноразовые Pre-Keys (пачка на устройство, каждый используется один раз).
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
    String,
    UniqueConstraint,
)

from app.base import Base


class PreKeyBundle(Base):
    """Хранит Identity Key и Signed Pre-Key устройства.

    Каждое устройство аккаунта публикует свой набор (signed_prekey + OPK);
    строки различаются по device_id (FK → user_devices.id). Ключ уникальности —
    (user_id, device_id), а не user_id: у аккаунта может быть несколько устройств.
    device_id=NULL — бандл без привязки к устройству (клиент без стабильного
    client_device_id либо доступ из тестового клиента без заголовка X-Device-Id).

    identity_key остаётся АККАУНТНЫМ X25519 (общий для устройств): переход на
    per-device identity требует проверки device→account cert, что придёт с fan-out.

    Attributes:
        user_id:           ID пользователя (FK → users.id).
        device_id:         ID устройства (FK → user_devices.id) или NULL.
        identity_key:      32 байта — X25519 публичный Identity Key аккаунта.
        signed_prekey:     32 байта — X25519 публичный Signed Pre-Key.
        signed_prekey_sig: 64 байта — Ed25519 подпись signed_prekey ключом identity_key.
        signed_prekey_id:  идентификатор SPK для ротации.
        created_at:        время публикации.
        updated_at:        время последнего обновления SPK.
    """

    __tablename__ = "prekey_bundles"
    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_prekey_bundle_user_device"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id = Column(
        Integer,
        ForeignKey("user_devices.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    identity_key = Column(LargeBinary(32), nullable=False)
    signed_prekey = Column(LargeBinary(32), nullable=False)
    signed_prekey_sig = Column(LargeBinary(64), nullable=False)
    signed_prekey_id = Column(Integer, nullable=False, default=0)
    # Separate Ed25519 identity public key (XEdDSA is out of
    # scope, so identity_key above is X25519-for-DH only and cannot itself sign).
    # signed_prekey_sig is verified against this key; identity_key_sig binds the
    # X25519 identity_key to this Ed25519 identity (Ed25519 signs the X25519 pub),
    # so a future out-of-band Ed25519 fingerprint transitively covers the DH key.
    # Nullable for backward compatibility with bundles published before this field existed.
    identity_key_ed = Column(LargeBinary(32), nullable=True)
    identity_key_sig = Column(LargeBinary(64), nullable=True)
    # Capability: клиент умеет ПРИНИМАТЬ v2 Double Ratchet.
    # NULL/False — пред-v2 бандл либо клиент без v2-приёма → отправитель
    # не шлёт v2 такому адресату (падает в v1).
    supports_v2 = Column(Boolean, nullable=True)
    # Device-identity тройка (публичные части). Forward-looking: отправитель
    # начнёт проверять cert и вести X3DH по device_x3dh_pub на fan-out; пока это
    # опубликованные, но неиспользуемые данные. cert подписывает аккаунтный
    # Ed25519 (identity_key_ed) над (client_device_id ‖ device_x3dh_pub ‖
    # device_sign_pub) — верификатор восстанавливает это сообщение из полей ниже.
    device_x3dh_pub = Column(LargeBinary(32), nullable=True)  # X25519 device X3DH pub (per-account)
    device_sign_pub = Column(LargeBinary(32), nullable=True)  # Ed25519 device signing pub
    device_cert_sig = Column(LargeBinary(64), nullable=True)  # Ed25519 подпись аккаунта над cert-сообщением
    client_device_id = Column(String(32), nullable=True)  # стабильный id устройства, подписанный в cert
    # PQXDH per-device Kyber pre-key (ML-KEM-768). Публичный подписан device
    # signing-ключом (как SPK); отправитель проверяет против device_sign_pub на
    # fan-out (та же цепочка, что SPK). Приватный — только на устройстве.
    # Nullable: бандлы до PQXDH и клиенты без ML-KEM остаются на классике.
    device_kyber_pub = Column(LargeBinary(1184), nullable=True)  # ML-KEM-768 pub (1184 байта)
    device_kyber_sig = Column(LargeBinary(64), nullable=True)  # Ed25519 подпись device-ключа над kyber pub
    device_kyber_id = Column(Integer, nullable=True)  # id pre-key для ротации (пока фикс)
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
        return f"<PreKeyBundle user_id={self.user_id} spk_id={self.signed_prekey_id}>"


class OneTimePreKey(Base):
    """Одноразовый Pre-Key для X3DH.

    Пользователь публикует пачку одноразовых ключей. При запросе Pre-Key Bundle
    один OPK выдаётся и помечается как использованный (used=True).
    Клиент должен пополнять пул при снижении количества доступных OPK.

    Attributes:
        user_id:    ID пользователя (FK → users.id).
        device_id:  ID устройства (FK → user_devices.id) или NULL — OPK свои
                    на устройство, чтобы выдавать OPK того же устройства, чей SPK.
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
    device_id = Column(
        Integer,
        ForeignKey("user_devices.id", ondelete="CASCADE"),
        nullable=True,
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
        return f"<OneTimePreKey user_id={self.user_id} key_id={self.key_id} used={self.used}>"


class OneTimeKyberPreKey(Base):
    """Одноразовый Kyber pre-key (ML-KEM-768) для PQXDH (ADR-006 P6).

    Зеркалит OneTimePreKey, но публичный — 1184 байта ML-KEM-768. Даёт KEM-
    forward-secrecy: каждая PQXDH-сессия предпочитает свежий PQOPK (используется
    один раз, удаляется у адресата), иначе fallback на last-resort PQSPK. Свои на
    устройство. Расходуется через /claim-opk (want_kyber=true) — только когда
    сессия реально идёт в PQ, иначе не-PQ трафик выжигал бы пул.
    """

    __tablename__ = "onetime_kyber_prekeys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id = Column(
        Integer,
        ForeignKey("user_devices.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    key_id = Column(Integer, nullable=False)
    public_key = Column(LargeBinary(1184), nullable=False)  # ML-KEM-768 pub
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<OneTimeKyberPreKey user_id={self.user_id} key_id={self.key_id} used={self.used}>"
