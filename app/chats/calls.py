"""
app/chats/calls.py — Call history API.

Tracks all voice/video calls (1-to-1 and group).
Provides a "recent calls" view for the Calls tab.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CallHistory, User
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/calls", tags=["calls"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class CallStartRequest(BaseModel):
    callee_id: int | None = None       # NULL for group calls
    room_id: int | None = None         # For group/voice channel calls
    call_type: str = Field(default="audio", pattern="^(audio|video|group_audio|group_video)$")


class CallEndRequest(BaseModel):
    call_id: int
    status: str = Field(default="answered", pattern="^(answered|missed|declined|busy)$")
    duration: int = Field(default=0, ge=0)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _call_dict(call: CallHistory, current_user_id: int, db: Session) -> dict:
    """Format a call record for API response."""
    # Determine the "other" user (for 1-to-1 calls)
    if call.caller_id == current_user_id:
        other_id = call.callee_id
        direction = "outgoing"
    else:
        other_id = call.caller_id
        direction = "incoming"

    other_user = None
    if other_id:
        u = db.query(User).filter(User.id == other_id).first()
        if u:
            other_user = {
                "user_id": u.id,
                "username": u.username,
                "display_name": u.display_name or u.username,
                "avatar_emoji": u.avatar_emoji or "👤",
                "avatar_url": u.avatar_url,
            }

    return {
        "id": call.id,
        "direction": direction,
        "call_type": call.call_type,
        "status": call.status,
        "duration": call.duration,
        "room_id": call.room_id,
        "other_user": other_user,
        "started_at": call.started_at.isoformat() if call.started_at else "",
        "ended_at": call.ended_at.isoformat() if call.ended_at else "",
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/recent")
async def recent_calls(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get recent calls for the current user (incoming + outgoing)."""
    calls = db.query(CallHistory).filter(
        or_(CallHistory.caller_id == u.id, CallHistory.callee_id == u.id)
    ).order_by(CallHistory.started_at.desc()).offset(offset).limit(limit).all()

    return {
        "calls": [_call_dict(c, u.id, db) for c in calls],
        "total": db.query(func.count(CallHistory.id)).filter(
            or_(CallHistory.caller_id == u.id, CallHistory.callee_id == u.id)
        ).scalar() or 0,
    }


@router.get("/missed")
async def missed_calls(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get missed calls."""
    calls = db.query(CallHistory).filter(
        CallHistory.callee_id == u.id,
        CallHistory.status == "missed",
    ).order_by(CallHistory.started_at.desc()).limit(50).all()

    return {"calls": [_call_dict(c, u.id, db) for c in calls]}


@router.post("/start", status_code=201)
async def start_call(body: CallStartRequest, u: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """Record a call start. Called by the initiator."""
    call = CallHistory(
        caller_id=u.id,
        callee_id=body.callee_id,
        room_id=body.room_id,
        call_type=body.call_type,
        status="missed",  # Default to missed, updated when answered/ended
    )
    db.add(call)
    db.commit()
    db.refresh(call)
    return {"call_id": call.id, "started_at": call.started_at.isoformat()}


@router.post("/end")
async def end_call(body: CallEndRequest, u: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """Record a call end. Updates status and duration."""
    call = db.query(CallHistory).filter(
        CallHistory.id == body.call_id,
        or_(CallHistory.caller_id == u.id, CallHistory.callee_id == u.id),
    ).first()
    if not call:
        raise HTTPException(404, "Call not found")

    call.status = body.status
    call.duration = body.duration
    call.ended_at = datetime.now(timezone.utc)
    db.commit()

    return {"ok": True, "call_id": call.id, "status": call.status, "duration": call.duration}


@router.delete("/clear")
async def clear_history(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Clear all call history for current user."""
    db.query(CallHistory).filter(
        or_(CallHistory.caller_id == u.id, CallHistory.callee_id == u.id)
    ).delete(synchronize_session=False)
    db.commit()
    return {"ok": True}


@router.delete("/{call_id}")
async def delete_call(call_id: int, u: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """Delete a call from history."""
    call = db.query(CallHistory).filter(
        CallHistory.id == call_id,
        or_(CallHistory.caller_id == u.id, CallHistory.callee_id == u.id),
    ).first()
    if not call:
        raise HTTPException(404, "Call not found")
    db.delete(call)
    db.commit()
    return {"ok": True}


@router.get("/stats")
async def call_stats(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get call statistics."""
    base = or_(CallHistory.caller_id == u.id, CallHistory.callee_id == u.id)
    total = db.query(func.count(CallHistory.id)).filter(base).scalar() or 0
    answered = db.query(func.count(CallHistory.id)).filter(
        base, CallHistory.status == "answered"
    ).scalar() or 0
    missed = db.query(func.count(CallHistory.id)).filter(
        base, CallHistory.status == "missed"
    ).scalar() or 0
    total_duration = db.query(func.sum(CallHistory.duration)).filter(
        base, CallHistory.status == "answered"
    ).scalar() or 0

    return {
        "total_calls": total,
        "answered": answered,
        "missed": missed,
        "declined": total - answered - missed,
        "total_duration_seconds": total_duration,
        "total_duration_human": _format_duration(total_duration),
    }


def _format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m"
