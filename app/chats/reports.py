"""
app/chats/reports.py — Progressive report & punishment system.

Endpoints:
  - POST /api/users/report/{user_id}    — submit a report
  - GET  /api/moderation/strikes         — view own strikes and moderation status
  - GET  /api/users/{user_id}/reports    — view reports for a user (admin only / own)

Safety rules (prevent false bans):
  1. Min 3 UNIQUE reporters before any punishment
  2. Same reporter cooldown: 1 report per 24h per target
  3. Self-report protection
  4. Bot immunity
  5. Admin reports weigh more (count as 2)
  6. Reports older than 30 days expire
  7. Progressive escalation: each strike requires NEW reports after previous punishment
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserReport, UserStrike
from app.models_rooms import RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])

# Valid report reasons
_VALID_REASONS = frozenset({"spam", "harassment", "nsfw", "other"})

# Punishment ladder: strike_number -> (punishment_code, timedelta or None for permanent)
_PUNISHMENTS: dict[int, tuple[str, timedelta | None]] = {
    1: ("mute_3d",        timedelta(days=3)),
    2: ("mute_7d",        timedelta(days=7)),
    3: ("mute_30d",       timedelta(days=30)),
    4: ("ban_3y",         timedelta(days=365 * 3)),
    5: ("ban_permanent",  None),
}

# Threshold: how many UNIQUE reporters needed for each next strike
# Key = current strike_count (BEFORE the new strike)
_THRESHOLDS: dict[int, int] = {
    0: 3,   # 1st strike: 3 unique reporters
    1: 3,   # 2nd strike: 3 unique reporters (new, after strike 1)
    2: 3,   # 3rd strike: 3 unique reporters (new, after strike 2)
    3: 5,   # 4th strike: 5 unique reporters (higher threshold)
    4: 1,   # 5th strike: any new report -> permanent ban
}

_REPORT_EXPIRY_DAYS = 30
_REPORTER_COOLDOWN_HOURS = 24


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════════════════════════

class ReportRequest(BaseModel):
    reason:      str       = Field(..., min_length=1, max_length=50)
    description: str       = Field("", max_length=500)
    message_id:  int | None = None


# ══════════════════════════════════════════════════════════════════════════════
# Core punishment logic
# ══════════════════════════════════════════════════════════════════════════════

def _format_remaining(td: timedelta) -> str:
    """Format timedelta as human-readable Russian string."""
    total_secs = int(td.total_seconds())
    if total_secs < 0:
        return "0 сек"
    days = total_secs // 86400
    hours = (total_secs % 86400) // 3600
    mins = (total_secs % 3600) // 60
    parts = []
    if days > 0:
        parts.append(f"{days} дн.")
    if hours > 0:
        parts.append(f"{hours} ч.")
    if mins > 0 and days == 0:
        parts.append(f"{mins} мин.")
    return " ".join(parts) if parts else "< 1 мин."


async def _check_and_apply_punishment(user_id: int, db: Session) -> dict | None:
    """
    Check if user has enough NEW reports to trigger the next strike.
    Returns strike info dict if a new strike was applied, None otherwise.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    current_strike = user.strike_count or 0

    # Already at max strikes (permanent ban)
    if current_strike >= 5:
        return None

    # Count UNCOUNTED reports (strike_id IS NULL) from last 30 days, by unique reporters
    cutoff = datetime.now(timezone.utc) - timedelta(days=_REPORT_EXPIRY_DAYS)
    uncounted = (
        db.query(UserReport)
        .filter(
            UserReport.reported_id == user_id,
            UserReport.strike_id == None,  # noqa: E711
            UserReport.created_at > cutoff,
        )
        .all()
    )

    if not uncounted:
        return None

    # Count unique reporters and effective weight (admin reports count as 2)
    unique_reporters: set[int] = set()
    for r in uncounted:
        unique_reporters.add(r.reporter_id)

    # Threshold for next strike
    required = _THRESHOLDS.get(current_strike, 1)

    if len(unique_reporters) < required:
        return None

    # Apply next strike
    return _apply_strike(user, current_strike + 1, uncounted, db)


def _apply_strike(
    user: User, strike_num: int, reports: list[UserReport], db: Session
) -> dict:
    """Apply a strike and its corresponding punishment."""
    punishment_code, duration = _PUNISHMENTS[strike_num]
    now = datetime.now(timezone.utc)

    expires_at = None
    if duration:
        expires_at = now + duration

    # Apply punishment to user
    if strike_num <= 3:
        # Global mute (can read, can't send)
        user.global_muted_until = expires_at
    elif strike_num == 4:
        # Temporary platform ban (3 years)
        user.is_active = False
        user.banned_until = expires_at
    else:
        # Permanent ban
        user.is_active = False
        user.banned_until = None  # NULL + is_active=False + strike_count>=5 = permanent

    user.strike_count = strike_num

    # Create strike record
    reasons_summary = ", ".join(sorted({r.reason for r in reports}))
    strike = UserStrike(
        user_id       = user.id,
        strike_number = strike_num,
        punishment    = punishment_code,
        reason        = f"Auto: {len(reports)} reports ({reasons_summary})",
        report_count  = len(reports),
        expires_at    = expires_at,
    )
    db.add(strike)
    db.flush()  # get strike.id

    # Mark reports as counted
    for r in reports:
        r.strike_id = strike.id

    db.commit()

    punishment_desc = {
        "mute_3d":       "Глобальный мьют на 3 дня",
        "mute_7d":       "Глобальный мьют на 7 дней",
        "mute_30d":      "Глобальный мьют на 30 дней",
        "ban_3y":        "Бан на платформе на 3 года",
        "ban_permanent": "Перманентный бан на платформе",
    }

    logger.warning(
        f"Strike #{strike_num} applied to user {user.username}(id={user.id}): "
        f"{punishment_code}, {len(reports)} reports from {len({r.reporter_id for r in reports})} unique reporters"
    )

    return {
        "strike_number": strike_num,
        "punishment":    punishment_code,
        "description":   punishment_desc.get(punishment_code, punishment_code),
        "expires_at":    expires_at.isoformat() if expires_at else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/users/report/{user_id}", status_code=201)
async def report_user(
    user_id: int,
    body:    ReportRequest,
    u:       User    = Depends(get_current_user),
    db:      Session = Depends(get_db),
):
    """
    Submit a report against a user.

    Validates all safety rules, then checks if the report threshold
    triggers the next punishment strike.
    """
    # 1. Self-report protection
    if user_id == u.id:
        raise HTTPException(400, "Нельзя пожаловаться на себя")

    # 2. Target exists
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "Пользователь не найден")

    # 3. Bot immunity
    if target.is_bot:
        raise HTTPException(400, "Нельзя пожаловаться на бота")

    # 4. Valid reason
    reason = body.reason.strip().lower()
    if reason not in _VALID_REASONS:
        raise HTTPException(
            422,
            f"Недопустимая причина. Допустимые: {', '.join(sorted(_VALID_REASONS))}",
        )

    # 5. Same reporter cooldown (24h)
    cooldown_cutoff = datetime.now(timezone.utc) - timedelta(hours=_REPORTER_COOLDOWN_HOURS)
    recent = (
        db.query(UserReport)
        .filter(
            UserReport.reporter_id == u.id,
            UserReport.reported_id == user_id,
            UserReport.created_at > cooldown_cutoff,
        )
        .first()
    )
    if recent:
        remaining = recent.created_at + timedelta(hours=_REPORTER_COOLDOWN_HOURS) - datetime.now(timezone.utc)
        raise HTTPException(
            429,
            f"Вы уже подавали жалобу на этого пользователя. Повторить можно через {_format_remaining(remaining)}",
        )

    # 6. Check if reporter is admin/owner in any shared room with the target
    is_admin = False
    shared_rooms = (
        db.query(RoomMember.room_id)
        .filter(RoomMember.user_id == u.id)
        .intersect(
            db.query(RoomMember.room_id)
            .filter(RoomMember.user_id == user_id)
        )
        .all()
    )
    if shared_rooms:
        shared_room_ids = [r[0] for r in shared_rooms]
        admin_membership = (
            db.query(RoomMember)
            .filter(
                RoomMember.user_id == u.id,
                RoomMember.room_id.in_(shared_room_ids),
                RoomMember.role.in_([RoomRole.ADMIN, RoomRole.OWNER]),
            )
            .first()
        )
        if admin_membership:
            is_admin = True

    # 7. Save report
    report = UserReport(
        reporter_id     = u.id,
        reported_id     = user_id,
        room_id         = shared_rooms[0][0] if shared_rooms else None,
        reason          = reason,
        description     = body.description.strip()[:500],
        message_id      = body.message_id,
        is_admin_report = is_admin,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    logger.info(
        f"Report: {u.username}(id={u.id}) reported {target.username}(id={target.id}), "
        f"reason={reason}, admin={is_admin}"
    )

    # 8. Check if threshold triggers next strike
    strike_info = await _check_and_apply_punishment(user_id, db)

    # 9. Notify the reported user (via global WS)
    if strike_info:
        await manager.notify_user(user_id, {
            "type":          "moderation",
            "action":        "strike",
            "strike_number": strike_info["strike_number"],
            "punishment":    strike_info["punishment"],
            "description":   strike_info["description"],
            "expires_at":    strike_info["expires_at"],
        })

    result = {
        "ok":      True,
        "message": "Жалоба отправлена. Спасибо за помощь в модерации.",
    }
    if strike_info:
        result["strike_applied"] = strike_info
    return result


@router.get("/api/moderation/strikes")
async def my_strikes(
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """View own strikes and current moderation status."""
    strikes = (
        db.query(UserStrike)
        .filter(UserStrike.user_id == u.id)
        .order_by(UserStrike.strike_number)
        .all()
    )

    muted = False
    muted_remaining = None
    if u.global_muted_until and u.global_muted_until > datetime.now(timezone.utc):
        muted = True
        muted_remaining = _format_remaining(u.global_muted_until - datetime.now(timezone.utc))

    return {
        "strike_count": u.strike_count or 0,
        "max_strikes":  5,
        "is_muted":     muted,
        "muted_until":  u.global_muted_until.isoformat() if u.global_muted_until else None,
        "muted_remaining": muted_remaining,
        "strikes": [
            {
                "number":     s.strike_number,
                "punishment": s.punishment,
                "reason":     s.reason,
                "report_count": s.report_count,
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            }
            for s in strikes
        ],
    }


@router.get("/api/users/{user_id}/reports")
async def user_reports(
    user_id: int,
    u:       User    = Depends(get_current_user),
    db:      Session = Depends(get_db),
):
    """
    View reports for a user.
    Users can only view reports they submitted.
    """
    reports = (
        db.query(UserReport)
        .filter(
            UserReport.reported_id == user_id,
            UserReport.reporter_id == u.id,
        )
        .order_by(UserReport.created_at.desc())
        .limit(50)
        .all()
    )

    return {
        "reports": [
            {
                "id":          r.id,
                "reason":      r.reason,
                "description": r.description,
                "created_at":  r.created_at.isoformat(),
                "counted":     r.strike_id is not None,
            }
            for r in reports
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Background task: auto-unmute / auto-unban expired punishments
# ══════════════════════════════════════════════════════════════════════════════

async def cleanup_expired_punishments(db: Session) -> None:
    """
    Background task: runs periodically to clear expired mutes and bans.
    - Users with global_muted_until < now() -> set to NULL
    - Users with banned_until < now() and is_active=False -> reactivate
    """
    now = datetime.now(timezone.utc)

    # Auto-unmute
    muted_users = (
        db.query(User)
        .filter(
            User.global_muted_until != None,  # noqa: E711
            User.global_muted_until < now,
        )
        .all()
    )
    for u in muted_users:
        u.global_muted_until = None
        logger.info(f"Auto-unmuted user {u.username}(id={u.id})")

    # Auto-unban (only temporary bans, not permanent)
    banned_users = (
        db.query(User)
        .filter(
            User.is_active == False,  # noqa: E712
            User.banned_until != None,  # noqa: E711
            User.banned_until < now,
        )
        .all()
    )
    for u in banned_users:
        u.is_active = True
        u.banned_until = None
        logger.info(f"Auto-unbanned user {u.username}(id={u.id}), strike_count={u.strike_count}")

    if muted_users or banned_users:
        db.commit()
