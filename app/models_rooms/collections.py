from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, UniqueConstraint, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base


class RoomTask(Base):
    """
    Задача в совместном списке задач комнаты.
    Любой участник может создать задачу; assignee_id -- необязательный ответственный.
    Удалять задачу может создатель или admin/owner.
    """
    __tablename__ = "room_tasks"

    id          = Column(Integer,     primary_key=True)
    room_id     = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    creator_id  = Column(Integer,     ForeignKey("users.id"), nullable=False)
    assignee_id = Column(Integer,     ForeignKey("users.id"), nullable=True)
    text        = Column(String(500), nullable=False)
    is_done     = Column(Boolean,     default=False)
    created_at  = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    creator  = relationship("User", foreign_keys=[creator_id])
    assignee = relationship("User", foreign_keys=[assignee_id])

    __table_args__ = (
        Index("ix_room_tasks_room", "room_id"),
    )


class SavedMessage(Base):
    """
    Сообщение, добавленное пользователем в избранное.
    Уникально по (user_id, message_id) -- нельзя сохранить одно сообщение дважды.
    """
    __tablename__ = "saved_messages"

    id         = Column(Integer,     primary_key=True)
    user_id    = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    message_id = Column(Integer,     ForeignKey("messages.id", ondelete="CASCADE"),
                        nullable=False)
    room_id    = Column(Integer,     nullable=False)
    note       = Column(String(200), nullable=True)
    saved_at   = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    message = relationship("Message")

    __table_args__ = (
        UniqueConstraint("user_id", "message_id"),
        Index("ix_saved_user", "user_id"),
    )
