"""
app/models/bot.py — Модели ботов и рецензий маркетплейса.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.base import Base


class Bot(Base):
    """
    Бот — серверная сущность, работающая через API-токен.

    owner_id — пользователь, создавший бота.
    user_id  — User-аккаунт бота (is_bot=True).
    """
    __tablename__ = "bots"

    id          = Column(Integer,     primary_key=True, index=True)
    user_id     = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    owner_id    = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    api_token   = Column(String(64),  unique=True, nullable=False, index=True)
    name        = Column(String(50),  nullable=False)
    description = Column(String(500), default="")
    avatar_url  = Column(String(255), nullable=True)
    is_active   = Column(Boolean,     default=True)
    created_at  = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    commands    = Column(Text,        default="[]")

    mini_app_url     = Column(String(500), nullable=True)
    mini_app_enabled = Column(Boolean,     default=False)

    # Marketplace
    is_public    = Column(Boolean,  default=False)
    category     = Column(String(30), default="other")
    installs     = Column(Integer,  default=0)
    rating       = Column(Float,    default=0.0)
    rating_count = Column(Integer,  default=0)

    owner    = relationship("User", foreign_keys=[owner_id])
    bot_user = relationship("User", foreign_keys=[user_id])


class BotReview(Base):
    """User review/rating for a marketplace bot."""
    __tablename__ = "bot_reviews"
    __table_args__ = (UniqueConstraint("bot_id", "user_id"),)

    id         = Column(Integer,     primary_key=True, index=True)
    bot_id     = Column(Integer,     ForeignKey("bots.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    rating     = Column(Integer,     CheckConstraint("rating >= 1 AND rating <= 5", name="ck_bot_reviews_rating_range"), nullable=False)
    text       = Column(String(500), default="")
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
