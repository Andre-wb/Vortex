"""
app/models/moderation.py — Система жалоб и прогрессивных наказаний.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.base import Base


class UserReport(Base):
    """
    Жалоба пользователя на другого пользователя.

    Правила безопасности (защита от ложных банов):
      - Нельзя пожаловаться на себя (CHECK constraint)
      - Один reporter — не чаще 1 раза в 24h на одного пользователя
      - Жалобы старше 30 дней не учитываются
      - Нужны жалобы от РАЗНЫХ пользователей (unique reporters)
      - Жалоба admin/owner = 2 обычных (is_admin_report=True)
    """
    __tablename__ = "user_reports"
    __table_args__ = (
        CheckConstraint("reporter_id != reported_id", name="ck_user_reports_no_self_report"),
    )

    id              = Column(Integer,     primary_key=True, index=True)
    reporter_id     = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    reported_id     = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    room_id         = Column(Integer,     nullable=True)
    reason          = Column(String(50),  nullable=False)   # spam, harassment, nsfw, other
    description     = Column(String(500), default="")
    message_id      = Column(Integer,     nullable=True)
    is_admin_report = Column(Boolean,     default=False)
    created_at      = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    strike_id       = Column(Integer,     ForeignKey("user_strikes.id", ondelete="SET NULL"), nullable=True)

    reporter = relationship("User", foreign_keys=[reporter_id])
    reported = relationship("User", foreign_keys=[reported_id])


class UserStrike(Base):
    """
    Страйк (наказание), наложенный автоматически.

    Strike 1: 3 unique reporters → mute 3 дня
    Strike 2: 3 новых reporters  → mute 7 дней
    Strike 3: 3 новых reporters  → mute 30 дней
    Strike 4: 5 новых reporters  → бан 3 года
    Strike 5: любая жалоба       → перманентный бан
    """
    __tablename__ = "user_strikes"

    id            = Column(Integer,     primary_key=True, index=True)
    user_id       = Column(Integer,     ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    strike_number = Column(Integer,     nullable=False)
    punishment    = Column(String(50),  nullable=False)   # mute_3d, mute_7d, mute_30d, ban_3y, ban_permanent
    reason        = Column(String(500), default="")
    report_count  = Column(Integer,     default=0)
    created_at    = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    expires_at    = Column(DateTime,    nullable=True)
