from __future__ import annotations

import enum


class RoomRole(str, enum.Enum):
    OWNER  = "owner"
    ADMIN  = "admin"
    MEMBER = "member"


class MessageType(str, enum.Enum):
    TEXT   = "text"
    FILE   = "file"
    IMAGE  = "image"
    VOICE  = "voice"
    SYSTEM = "system"
