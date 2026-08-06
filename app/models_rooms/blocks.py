# real block model so blocking persists independently of any DM room
"""
app/models_rooms/blocks.py — Модель блокировок пользователей.

Блокировка хранится как отдельная запись (blocker → blocked), а не как
RoomMember.is_banned на конкретной DM-комнате. Это закрывает обход, при
котором заблокированный пользователь открывал новый DM и продолжал писать.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, UniqueConstraint

from app.base import Base


class BlockedUser(Base):
    """Одна запись = «blocker_id заблокировал blocked_id»."""

    __tablename__ = "blockedusers"
    __table_args__ = (UniqueConstraint("blocker_id", "blocked_id"),)

    id = Column(Integer, primary_key=True, index=True)
    blocker_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    blocked_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
