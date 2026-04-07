"""
app/chats/statuses.py -- 24-hour ephemeral status/story API.

Users can post short text statuses visible to their contacts for 24 hours.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserStatus
from app.models.contact import Contact
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["statuses"])


class StatusRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)


@router.post("/api/statuses")
async def post_status(
    body: StatusRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new 24-hour status."""
    status = UserStatus(
        user_id=u.id,
        text=body.text,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(status)
    db.commit()
    db.refresh(status)
    return {"ok": True, "id": status.id}


@router.get("/api/statuses")
async def get_statuses(
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get active statuses from contacts and self."""
    contact_ids = [
        c.contact_id
        for c in db.query(Contact).filter(Contact.owner_id == u.id).all()
    ]
    contact_ids.append(u.id)

    now = datetime.now(timezone.utc)
    statuses = (
        db.query(UserStatus)
        .filter(
            UserStatus.user_id.in_(contact_ids),
            UserStatus.expires_at > now,
        )
        .order_by(UserStatus.created_at.desc())
        .all()
    )

    result: dict[int, dict] = {}
    for s in statuses:
        uid = s.user_id
        if uid not in result:
            user = db.query(User).filter(User.id == uid).first()
            result[uid] = {
                "user_id": uid,
                "username": user.username if user else "?",
                "display_name": user.display_name if user else "?",
                "avatar_emoji": user.avatar_emoji if user else "\U0001F464",
                "avatar_url": getattr(user, "avatar_url", None),
                "custom_status": getattr(user, "custom_status", None),
                "status_emoji": getattr(user, "status_emoji", None),
                "presence": getattr(user, "presence", "online") or "online",
                "statuses": [],
            }
        result[uid]["statuses"].append({
            "id": s.id,
            "text": s.text,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
        })

    return {"users": list(result.values())}


async def cleanup_expired_statuses(db: Session) -> int:
    """Delete expired statuses. Called from background task."""
    now = datetime.now(timezone.utc)
    count = db.query(UserStatus).filter(UserStatus.expires_at <= now).delete()
    if count:
        db.commit()
    return count
