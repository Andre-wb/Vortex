from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, Text, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base


class Topic(Base):
    """
    Topic внутри комнаты -- отдельный поток дискуссии.
    Аналог Telegram Topics / Discord Forum Channels.
    """
    __tablename__ = "topics"

    id          = Column(Integer,     primary_key=True, index=True)
    room_id     = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    title       = Column(String(200), nullable=False)
    icon_emoji  = Column(String(10),  default="\U0001f4ac")
    creator_id  = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    is_pinned   = Column(Boolean,     default=False)
    is_closed   = Column(Boolean,     default=False)  # Closed = no new messages
    message_count = Column(Integer,   default=0)
    last_message_at = Column(DateTime, nullable=True)
    created_at  = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_topic_room", "room_id"),
    )


class ForumThread(Base):
    """
    Forum thread -- длинная дискуссия с заголовком и тегами.
    Комната с is_forum=True становится форумом.
    """
    __tablename__ = "forum_threads"

    id          = Column(Integer,     primary_key=True, index=True)
    room_id     = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    title       = Column(String(300), nullable=False)
    body        = Column(Text,        default="")  # Encrypted first message
    creator_id  = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    tags        = Column(Text,        default="[]")  # JSON array of tag strings
    is_pinned   = Column(Boolean,     default=False)
    is_locked   = Column(Boolean,     default=False)
    is_solved   = Column(Boolean,     default=False)  # Q&A mode
    reply_count = Column(Integer,     default=0)
    upvotes     = Column(Integer,     default=0)
    last_reply_at = Column(DateTime,  nullable=True)
    created_at  = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_forum_room_created", "room_id", "created_at"),
    )
