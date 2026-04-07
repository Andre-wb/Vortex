"""
app/models/ — Доменные модели SQLAlchemy и Pydantic-схемы.

Структура:
  user.py        — User, UserDevice, RefreshToken, UserStatus + схемы аутентификации
  bot.py         — Bot, BotReview
  moderation.py  — UserReport, UserStrike
  media.py       — CallHistory, UploadQuota, PushSubscription
  contact.py     — Contact
"""
from app.models.user import (
    User,
    UserDevice,
    RefreshToken,
    UserStatus,
    KeyBackup,
    DeviceLinkRequest,
    SyncEvent,
    DeviceCrossSign,
    SecretShare,
    FederatedBackupShard,
    KeyTransparencyEntry,
    RegisterRequest,
    LoginRequest,
    KeyLoginRequest,
    SeedLoginRequest,
    UpdateProfileRequest,
    UpdateRichStatusRequest,
    PasswordStrengthRequest,
    TwoFAVerifyRequest,
    TwoFALoginRequest,
)
from app.models.bot import Bot, BotReview
from app.models.moderation import UserReport, UserStrike
from app.models.media import CallHistory, UploadQuota, PushSubscription
from app.models.contact import Contact

__all__ = [
    # user
    "User", "UserDevice", "RefreshToken", "UserStatus", "KeyBackup", "DeviceLinkRequest", "SyncEvent", "DeviceCrossSign", "SecretShare", "FederatedBackupShard", "KeyTransparencyEntry",
    "RegisterRequest", "LoginRequest", "KeyLoginRequest", "SeedLoginRequest",
    "UpdateProfileRequest", "UpdateRichStatusRequest",
    "PasswordStrengthRequest", "TwoFAVerifyRequest", "TwoFALoginRequest",
    # bot
    "Bot", "BotReview",
    # moderation
    "UserReport", "UserStrike",
    # media
    "CallHistory", "UploadQuota", "PushSubscription",
    # contact
    "Contact",
]
