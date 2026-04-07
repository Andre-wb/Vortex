from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, UniqueConstraint, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base
from app.models_rooms.enums import RoomRole


class Space(Base):
    """
    Пространство (аналог Discord-сервера / Slack-воркспейса).
    Группирует несколько комнат с общим членством и правами.
    """
    __tablename__ = "spaces"

    id           = Column(Integer,     primary_key=True, index=True)
    name         = Column(String(100), nullable=False)
    description  = Column(String(500), default="")
    avatar_emoji = Column(String(10),  default="\U0001f3e0")
    avatar_url   = Column(String(255), nullable=True)
    creator_id   = Column(Integer,     ForeignKey("users.id"), nullable=False)
    invite_code  = Column(String(16),  unique=True, nullable=False, index=True)
    is_public    = Column(Boolean,     default=False)
    member_count = Column(Integer,     default=0)
    created_at   = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    # Nested spaces
    parent_id    = Column(Integer,     ForeignKey("spaces.id", ondelete="SET NULL"), nullable=True)

    # Vanity URL: vortex.example.com/s/my-space
    vanity_url   = Column(String(50),  unique=True, nullable=True, index=True)

    # Onboarding
    welcome_message = Column(Text,     default="")     # Markdown welcome text
    rules           = Column(Text,     default="")     # Community rules (Markdown)
    onboarding_roles = Column(Text,    default="[]")   # JSON: selectable roles on join

    # Template
    template_id  = Column(String(30),  nullable=True)  # "gaming", "community", "study", etc.

    # Per-space theme: JSON {"wallpaper": "stars|aurora|...", "accent": "#hex", "dark_mode": bool}
    theme_json   = Column(Text,        nullable=True)

    members    = relationship("SpaceMember",   back_populates="space",
                              cascade="all, delete-orphan")
    categories = relationship("SpaceCategory", back_populates="space",
                              cascade="all, delete-orphan")
    rooms      = relationship("Room",          backref="space",
                              foreign_keys="[Room.space_id]")


class SpaceMember(Base):
    """Участник пространства. Роли переиспользуются из RoomRole."""
    __tablename__ = "space_members"

    id        = Column(Integer,        primary_key=True)
    space_id  = Column(Integer,        ForeignKey("spaces.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    user_id   = Column(Integer,        ForeignKey("users.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    role      = Column(Enum(RoomRole), default=RoomRole.MEMBER)
    joined_at = Column(DateTime,       default=lambda: datetime.now(timezone.utc))

    space = relationship("Space", back_populates="members")
    user  = relationship("User")

    __table_args__ = (
        UniqueConstraint("space_id", "user_id"),
        Index("ix_sm_space_user", "space_id", "user_id"),
    )


class SpaceCategory(Base):
    """Категория (папка) внутри пространства для группировки комнат."""
    __tablename__ = "space_categories"

    id        = Column(Integer,    primary_key=True)
    space_id  = Column(Integer,    ForeignKey("spaces.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    name      = Column(String(50), nullable=False)
    order_idx = Column(Integer,    default=0)

    space = relationship("Space", back_populates="categories")
    rooms = relationship("Room",  backref="category",
                         foreign_keys="[Room.category_id]")
