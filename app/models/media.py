"""
app/models/media.py — Модели файлов, звонков и push-подписок.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import relationship

from app.base import Base


class CallHistory(Base):
    """
    История звонков — metadata-private.

    caller_id и callee_id хранятся для функциональности (missed calls UI),
    но НЕ раскрывают социальный граф если БД скомпрометирована:
    - caller_pseudo / callee_pseudo — sealed sender псевдонимы (BLAKE2b)
    - encrypted_meta — AES-encrypted JSON с деталями (client-side key)
    - Сервер видит только псевдонимы, не может связать с user_id без секрета
    """
    __tablename__ = "call_history"

    id          = Column(Integer,    primary_key=True, index=True)
    caller_id   = Column(Integer,    ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    callee_id   = Column(Integer,    ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    room_id     = Column(Integer,    ForeignKey("rooms.id", ondelete="SET NULL"), nullable=True)
    call_type   = Column(String(20), default="audio")   # audio, video, group_audio, group_video
    status      = Column(String(20), default="missed")  # answered, missed, declined, busy
    duration    = Column(Integer,    default=0)          # seconds
    started_at  = Column(DateTime,   default=lambda: datetime.now(timezone.utc))
    ended_at    = Column(DateTime,   nullable=True)
    seen        = Column(Boolean,    default=False, server_default="0")

    # Privacy fields: sealed pseudonyms (server cannot link to user_id without secret)
    caller_pseudo = Column(String(64), nullable=True)  # BLAKE2b sealed sender pseudo
    callee_pseudo = Column(String(64), nullable=True)
    # Client-encrypted metadata (call details encrypted with room key)
    encrypted_meta = Column(String(2048), nullable=True)  # hex AES-GCM blob

    caller = relationship("User", foreign_keys=[caller_id])
    callee = relationship("User", foreign_keys=[callee_id])

    __table_args__ = (
        Index("ix_calls_caller", "caller_id", "started_at"),
        Index("ix_calls_callee", "callee_id", "started_at"),
    )


class UploadQuota(Base):
    """Учёт загрузок для квотирования по пользователю и IP."""
    __tablename__ = "upload_quotas"

    id          = Column(Integer,    primary_key=True, index=True)
    user_id     = Column(Integer,    nullable=True, index=True)
    client_ip   = Column(String(45), nullable=True, index=True)
    file_size   = Column(Integer,    nullable=True)
    file_hash   = Column(String(64), nullable=True)
    uploaded_at = Column(DateTime,   default=lambda: datetime.now(timezone.utc), index=True)


class PushSubscription(Base):
    """Web Push подписка пользователя (VAPID)."""
    __tablename__ = "push_subscriptions"

    id         = Column(Integer,     primary_key=True, index=True)
    user_id    = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint   = Column(String(512), nullable=False, unique=True)
    p256dh     = Column(String(256), nullable=False)
    auth       = Column(String(256), nullable=False)
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
