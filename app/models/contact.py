"""
app/models/contact.py — Модель контактов пользователей.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.base import Base


class Contact(Base):
    __tablename__ = "contacts"

    id         = Column(Integer,      primary_key=True, index=True)
    owner_id   = Column(Integer,      ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    contact_id = Column(Integer,      ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    nickname   = Column(String(100),  nullable=True)
    created_at = Column(DateTime,     default=lambda: datetime.now(timezone.utc))

    fingerprint_verified    = Column(Boolean,  default=False, nullable=False, server_default="0")
    fingerprint_verified_at = Column(DateTime, nullable=True)
    fingerprint_pubkey_hash = Column(String(64), nullable=True)

    owner   = relationship("User", foreign_keys=[owner_id])
    contact = relationship("User", foreign_keys=[contact_id])

    __table_args__ = (UniqueConstraint("owner_id", "contact_id"),)
