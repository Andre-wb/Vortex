from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, Text, UniqueConstraint, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base


class PostView(Base):
    """Track views per post (message) in a channel."""
    __tablename__ = "post_views"

    id         = Column(Integer,  primary_key=True)
    message_id = Column(Integer,  ForeignKey("messages.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    user_id    = Column(Integer,  ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False)
    viewed_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("message_id", "user_id"),
        Index("ix_pv_msg", "message_id"),
    )


class PostReaction(Base):
    """Poll-style reactions on channel posts (multiple emoji per post)."""
    __tablename__ = "post_reactions"

    id         = Column(Integer,  primary_key=True)
    message_id = Column(Integer,  ForeignKey("messages.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    user_id    = Column(Integer,  ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False)
    emoji      = Column(String(10), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("message_id", "user_id", "emoji"),
    )


class ChannelMonetization(Base):
    """Monetization settings for a channel (wallet, price, currency)."""
    __tablename__ = "channel_monetization"

    id           = Column(Integer,     primary_key=True)
    room_id      = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                          unique=True, nullable=False, index=True)
    wallet_address = Column(String(255), nullable=False)  # TON/USDT/BTC address
    currency     = Column(String(20),  default="USDT")    # USDT, TON, BTC
    network      = Column(String(20),  default="trc20")   # trc20, ton, btc-lightning
    price_monthly = Column(Integer,    default=0)          # Price in smallest unit (cents/nanoton)
    price_display = Column(String(50), default="Free")     # "5 USDT", "1 TON", "Free"
    is_paid      = Column(Boolean,     default=False)
    donations_enabled = Column(Boolean, default=True)
    created_at   = Column(DateTime,    default=lambda: datetime.now(timezone.utc))


class ChannelSubscription(Base):
    """Paid subscription for a channel."""
    __tablename__ = "channel_subscriptions"

    id         = Column(Integer,     primary_key=True)
    room_id    = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False)
    tx_hash    = Column(String(255), nullable=True)   # Blockchain transaction hash
    amount     = Column(String(50),  nullable=True)   # "5 USDT"
    expires_at = Column(DateTime,    nullable=False)
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_chsub_room_user", "room_id", "user_id"),
    )


class ChannelDonation(Base):
    """Donation (one-time payment) to channel author."""
    __tablename__ = "channel_donations"

    id         = Column(Integer,     primary_key=True)
    room_id    = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=True)
    tx_hash    = Column(String(255), nullable=True)
    amount     = Column(String(50),  nullable=False)  # "10 USDT"
    message    = Column(String(200), default="")      # Donor message
    currency   = Column(String(20),  default="USDT")
    created_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))


class UserSlowmode(Base):
    """
    Per-user slowmode override in a room.
    Allows different cooldowns for different users (stricter for spammers).
    """
    __tablename__ = "user_slowmodes"

    id        = Column(Integer, primary_key=True)
    room_id   = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"),
                       nullable=False)
    user_id   = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                       nullable=False)
    cooldown_seconds = Column(Integer, default=30)
    set_by    = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("room_id", "user_id"),
        Index("ix_uslowmode_room_user", "room_id", "user_id"),
    )
