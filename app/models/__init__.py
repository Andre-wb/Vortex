"""
app/models/ — Доменные модели SQLAlchemy и Pydantic-схемы.

Структура:
  user.py        — User, UserDevice, RefreshToken, UserStatus + схемы аутентификации
  bot.py         — Bot, BotReview
  moderation.py  — UserReport, UserStrike
  media.py       — CallHistory, UploadQuota, PushSubscription
  contact.py     — Contact
"""

from app.models.bot import Bot, BotReview
from app.models.contact import Contact
from app.models.media import CallHistory, PushSubscription, UploadQuota
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
    "BotReview",
    # media
    "CallHistory",
    # contact
    "Contact",
    "DeviceCrossSign",
    "DeviceLinkRequest",
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
