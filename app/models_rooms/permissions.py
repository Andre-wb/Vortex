from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, Index,
)
from sqlalchemy.orm import relationship

from app.base import Base
from app.models_rooms.enums import RoomRole


class Permission(Base):
    """
    Granular permission override per role or per user in a room.

    Permissions are stored as JSON bitfield.
    Each permission is a bit in a 64-bit integer.
    """
    __tablename__ = "permissions"

    id        = Column(Integer, primary_key=True)
    room_id   = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    # Either role-based or user-specific override
    role      = Column(Enum(RoomRole), nullable=True)   # NULL = user-specific
    user_id   = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                       nullable=True)                    # NULL = role-based
    allow     = Column(Integer, default=0, nullable=False)  # Bitfield: allowed permissions
    deny      = Column(Integer, default=0, nullable=False)  # Bitfield: denied permissions

    __table_args__ = (
        Index("ix_perm_room", "room_id"),
    )


class PermissionFlags:
    """
    40+ granular permission flags (Discord-style).

    Usage:
        has_perm = (member_allow & PermissionFlags.SEND_MESSAGES) != 0
    """
    # General
    VIEW_CHANNEL         = 1 << 0
    MANAGE_CHANNEL       = 1 << 1
    MANAGE_PERMISSIONS   = 1 << 2

    # Membership
    CREATE_INVITE        = 1 << 3
    KICK_MEMBERS         = 1 << 4
    BAN_MEMBERS          = 1 << 5
    MANAGE_MEMBERS       = 1 << 6

    # Messages
    SEND_MESSAGES        = 1 << 7
    SEND_MEDIA           = 1 << 8
    SEND_FILES           = 1 << 9
    SEND_LINKS           = 1 << 10
    SEND_STICKERS        = 1 << 11
    SEND_POLLS           = 1 << 12
    EMBED_LINKS          = 1 << 13
    ATTACH_FILES         = 1 << 14
    USE_REACTIONS        = 1 << 15
    USE_MENTIONS         = 1 << 16
    MENTION_EVERYONE     = 1 << 17

    # Message management
    MANAGE_MESSAGES      = 1 << 18  # Delete others' messages
    PIN_MESSAGES         = 1 << 19
    EDIT_MESSAGES        = 1 << 20  # Edit own messages

    # Threads & Topics
    CREATE_TOPICS        = 1 << 21
    MANAGE_TOPICS        = 1 << 22
    CREATE_THREADS       = 1 << 23
    MANAGE_THREADS       = 1 << 24
    SEND_IN_THREADS      = 1 << 25

    # Voice
    CONNECT_VOICE        = 1 << 26
    SPEAK                = 1 << 27
    STREAM_VIDEO         = 1 << 28
    MUTE_MEMBERS         = 1 << 29
    DEAFEN_MEMBERS       = 1 << 30
    MOVE_MEMBERS         = 1 << 31
    USE_VOICE_ACTIVITY   = 1 << 32
    PRIORITY_SPEAKER     = 1 << 33

    # Advanced
    MANAGE_WEBHOOKS      = 1 << 34
    MANAGE_BOTS          = 1 << 35
    VIEW_AUDIT_LOG       = 1 << 36
    MANAGE_SPACE         = 1 << 37
    MANAGE_ROLES         = 1 << 38
    MANAGE_EMOJI         = 1 << 39
    ADMINISTRATOR        = 1 << 40  # Bypass all checks

    # Presets
    DEFAULT_MEMBER = (
        VIEW_CHANNEL | SEND_MESSAGES | SEND_MEDIA | SEND_FILES |
        SEND_LINKS | SEND_STICKERS | SEND_POLLS | USE_REACTIONS |
        USE_MENTIONS | EDIT_MESSAGES | CREATE_THREADS |
        SEND_IN_THREADS | CONNECT_VOICE | SPEAK | USE_VOICE_ACTIVITY
    )
    DEFAULT_ADMIN = DEFAULT_MEMBER | (
        MANAGE_CHANNEL | CREATE_INVITE | KICK_MEMBERS | BAN_MEMBERS |
        MANAGE_MESSAGES | PIN_MESSAGES | CREATE_TOPICS | MANAGE_TOPICS |
        MANAGE_THREADS | MUTE_MEMBERS | MOVE_MEMBERS | VIEW_AUDIT_LOG |
        MANAGE_BOTS | MANAGE_MEMBERS
    )
    DEFAULT_OWNER = (1 << 41) - 1  # All permissions

    @classmethod
    def all_flags(cls) -> dict[str, int]:
        """Return dict of all permission flag names and values."""
        return {
            name: value for name, value in vars(cls).items()
            if isinstance(value, int) and name.isupper() and not name.startswith("DEFAULT")
        }


class AutoModRule(Base):
    """
    Auto-moderation rule for a room.
    Triggered automatically when a message matches the pattern.

    Actions: warn, mute, kick, ban, delete
    """
    __tablename__ = "automod_rules"

    id          = Column(Integer,     primary_key=True, index=True)
    room_id     = Column(Integer,     ForeignKey("rooms.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    name        = Column(String(100), nullable=False)
    is_enabled  = Column(Boolean,     default=True)

    # Rule type: "regex", "word_filter", "link_whitelist", "spam_detection", "caps_filter"
    rule_type   = Column(String(30),  nullable=False, default="word_filter")

    # Pattern: regex pattern or JSON list of words/domains
    pattern     = Column(Text,        nullable=False)

    # Action on match
    action      = Column(String(20),  default="delete")  # warn, delete, mute, kick, ban
    mute_duration_seconds = Column(Integer, default=300)  # For mute action

    # Exempt roles (JSON list: ["admin", "owner"])
    exempt_roles = Column(Text,       default='["owner", "admin"]')

    creator_id  = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    trigger_count = Column(Integer,   default=0)
    created_at  = Column(DateTime,    default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_automod_room", "room_id"),
    )
