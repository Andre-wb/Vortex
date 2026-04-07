from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Column, DateTime, ForeignKey,
    Integer, String, Text, UniqueConstraint, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base


class AuditLog(Base):
    """
    Audit log entry for a space or room.
    Tracks all moderation and configuration changes.
    """
    __tablename__ = "audit_logs"

    id         = Column(Integer,     primary_key=True, index=True)
    space_id   = Column(Integer,     ForeignKey("spaces.id", ondelete="CASCADE"),
                        nullable=True, index=True)
    room_id    = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                        nullable=True)
    actor_id   = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True)
    action     = Column(String(50),  nullable=False)  # "member_kick", "role_change", "channel_create", etc.
    target_id  = Column(Integer,     nullable=True)   # Target user/room/category ID
    details    = Column(Text,        default="{}")    # JSON with extra context
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_audit_space", "space_id", "created_at"),
    )


class SpaceEmoji(Base):
    """Custom emoji uploaded for a specific space."""
    __tablename__ = "space_emojis"

    id         = Column(Integer,     primary_key=True)
    space_id   = Column(Integer,     ForeignKey("spaces.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    name       = Column(String(50),  nullable=False)   # :emoji_name:
    image_url  = Column(String(255), nullable=False)
    creator_id = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("space_id", "name"),
    )
