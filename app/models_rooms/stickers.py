from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, UniqueConstraint, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base


class StickerPack(Base):
    """Набор стикеров. Создатель может загружать стикеры и управлять паком."""
    __tablename__ = "sticker_packs"

    id          = Column(Integer,     primary_key=True, index=True)
    name        = Column(String(50),  nullable=False)
    description = Column(String(200), default="")
    creator_id  = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    cover_url   = Column(String(255), nullable=True)
    is_public   = Column(Boolean,     default=True)
    created_at  = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    stickers = relationship("Sticker", back_populates="pack",
                            cascade="all, delete-orphan")
    creator  = relationship("User")


class Sticker(Base):
    """Отдельный стикер внутри набора."""
    __tablename__ = "stickers"

    id         = Column(Integer,     primary_key=True, index=True)
    pack_id    = Column(Integer,     ForeignKey("sticker_packs.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    emoji      = Column(String(10),  default="\U0001f600")
    image_url  = Column(String(255), nullable=False)
    order_idx  = Column(Integer,     default=0)
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    pack = relationship("StickerPack", back_populates="stickers")


class UserFavoritePack(Base):
    """Избранный набор стикеров пользователя."""
    __tablename__ = "user_favorite_packs"

    id       = Column(Integer,  primary_key=True)
    user_id  = Column(Integer,  ForeignKey("users.id", ondelete="CASCADE"),
                      nullable=False, index=True)
    pack_id  = Column(Integer,  ForeignKey("sticker_packs.id", ondelete="CASCADE"),
                      nullable=False)
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    pack = relationship("StickerPack")

    __table_args__ = (
        UniqueConstraint("user_id", "pack_id"),
        Index("ix_ufp_user", "user_id"),
    )
