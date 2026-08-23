"""
app/models/ — Доменные модели SQLAlchemy и Pydantic-схемы.

Структура:
  user.py        — User, UserDevice, RefreshToken, UserStatus + схемы аутентификации
  bot.py         — Bot, BotReview, BotWebhook, BotScope, BotInlineResults
  moderation.py  — UserReport, UserStrike
  media.py       — CallHistory, UploadQuota, PushSubscription, UnifiedPushSubscription,
                   DistributedFile, DistributedChunk
  contact.py     — Contact
"""

from app.models.bot import Bot, BotInlineResults, BotReview, BotScope, BotWebhook
from app.models.contact import Contact
from app.models.media import (
    CallHistory,
    DistributedChunk,
    DistributedFile,
    PushSubscription,
    UnifiedPushSubscription,
    UploadQuota,
)
from app.models.moderation import UserReport, UserStrike
from app.models.prekeys import OneTimeKyberPreKey, OneTimePreKey, PreKeyBundle
from app.models.user import (
    DeviceCrossSign,
    DeviceLinkRequest,
    FederatedBackupShard,
    KeyBackup,
    KeyLoginRequest,
    KeyTransparencyEntry,
    LoginRequest,
    PasswordStrengthRequest,
    RefreshToken,
    RegisterRequest,
    SecretShare,
    SeedLoginRequest,
    SyncEvent,
    TwoFALoginRequest,
    TwoFAVerifyRequest,
    UpdateProfileRequest,
    UpdateRichStatusRequest,
    User,
    UserDevice,
    UserStatus,
    VerificationAttestation,
)

__all__ = [
    # bot
    "Bot",
    "BotInlineResults",
    "BotReview",
    "BotScope",
    "BotWebhook",
    # media
    "CallHistory",
    # contact
    "Contact",
    "DeviceCrossSign",
    "DeviceLinkRequest",
    "DistributedChunk",
    "DistributedFile",
    "FederatedBackupShard",
    "KeyBackup",
    "KeyLoginRequest",
    "KeyTransparencyEntry",
    "LoginRequest",
    "OneTimeKyberPreKey",
    "OneTimePreKey",
    "PasswordStrengthRequest",
    # prekeys (Double Ratchet / X3DH)
    "PreKeyBundle",
    "PushSubscription",
    "RefreshToken",
    "RegisterRequest",
    "SecretShare",
    "SeedLoginRequest",
    "SyncEvent",
    "TwoFALoginRequest",
    "TwoFAVerifyRequest",
    "UnifiedPushSubscription",
    "UpdateProfileRequest",
    "UpdateRichStatusRequest",
    "UploadQuota",
    # user
    "User",
    "UserDevice",
    # moderation
    "UserReport",
    "UserStatus",
    "UserStrike",
    "VerificationAttestation",
]
