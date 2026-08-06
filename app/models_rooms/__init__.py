"""
app/models_rooms — Модели комнат, сообщений, файлов и распределённых ключей.

Разбит на подмодули. Все классы реэкспортируются здесь для обратной совместимости:
    from app.models_rooms import Room, RoomMember, Message, ...
"""
from app.models_rooms.admin import AuditLog, SpaceEmoji
from app.models_rooms.analytics import (
    ChannelDonation,
    ChannelMonetization,
    ChannelSubscription,
    PostReaction,
    PostView,
    UserSlowmode,
)
from app.models_rooms.blocks import BlockedUser  # register block model
from app.models_rooms.collections import RoomTask, SavedMessage
from app.models_rooms.discussions import ForumThread, Topic
from app.models_rooms.encryption import (
    EncryptedRoomKey,
    PendingKeyRequest,
    PendingNotification,
    RoomInvite,
    RoomInviteEscrow,
    SealedKeyPackage,
)
from app.models_rooms.enums import MessageType, RoomRole
from app.models_rooms.federation import FederatedEnvelope, PersistedFederatedRoom, Story, StoryKeyEnvelope
from app.models_rooms.feeds import ChannelFeed
from app.models_rooms.messages import FileTransfer, Message, MessageEditHistory, MessageReaction
from app.models_rooms.permissions import AutoModRule, Permission, PermissionFlags
from app.models_rooms.public_keys import PublicRoomKey
from app.models_rooms.rooms import JoinRequest, Room, RoomMember
from app.models_rooms.spaces import Space, SpaceCategory, SpaceMember
from app.models_rooms.stickers import SavedGif, Sticker, StickerPack, UserFavoritePack

__all__ = [
    # admin
    "AuditLog",
    "AutoModRule",
    # blocks
    "BlockedUser",
    "ChannelDonation",
    # feeds
    "ChannelFeed",
    "ChannelMonetization",
    "ChannelSubscription",
    # encryption
    "EncryptedRoomKey",
    "FederatedEnvelope",
    "FileTransfer",
    "ForumThread",
    "JoinRequest",
    # messages
    "Message",
    "MessageEditHistory",
    "MessageReaction",
    "MessageType",
    "PendingKeyRequest",
    "PendingNotification",
    # permissions
    "Permission",
    "PermissionFlags",
    # federation
    "PersistedFederatedRoom",
    "PostReaction",
    # analytics
    "PostView",
    "PublicRoomKey",
    # rooms
    "Room",
    "RoomInvite",
    "RoomInviteEscrow",
    "RoomMember",
    # enums
    "RoomRole",
    # collections
    "RoomTask",
    "SavedGif",
    "SavedMessage",
    "SealedKeyPackage",
    # spaces
    "Space",
    "SpaceCategory",
    "SpaceEmoji",
    "SpaceMember",
    "Sticker",
    # stickers
    "StickerPack",
    "Story",
    "StoryKeyEnvelope",
    # discussions
    "Topic",
    "UserFavoritePack",
    "UserSlowmode",
]
