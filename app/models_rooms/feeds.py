from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, Text, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base


class ChannelFeed(Base):
    """RSS feed or incoming webhook auto-posting for a broadcast channel."""
    __tablename__ = "channel_feeds"

    id            = Column(Integer,     primary_key=True, autoincrement=True)
    room_id       = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    feed_type     = Column(String(20),  nullable=False)   # "rss" | "webhook"
    url           = Column(Text,        nullable=False)   # RSS URL or webhook secret key
    last_fetched  = Column(DateTime,    nullable=True)
    last_item_id  = Column(Text,        nullable=True)    # last seen RSS item guid
    is_active     = Column(Boolean,     default=True)
    created_at    = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
