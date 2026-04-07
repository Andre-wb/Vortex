"""
app/chats/group_calls.py — Ad-hoc group calls with invite/accept/decline lifecycle.

Unlike voice channels (persistent, join-anytime), group calls are initiated
by a user, ring for all room members, and end when everyone leaves or the
initiator ends the call.  State is in-memory (like voice.py).
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Room, RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/group-calls", tags=["group-calls"])

# ── In-memory state ─────────────────────────────────────────────────────────

@dataclass
class GroupCallParticipant:
    user_id: int
    username: str
    display_name: str
    avatar_emoji: str
    avatar_url: Optional[str]
    state: str = "invited"          # invited | ringing | connecting | connected | left | declined
    joined_at: Optional[datetime] = None
    is_muted: bool = False
    is_video: bool = False
    is_screen_sharing: bool = False

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "avatar_emoji": self.avatar_emoji,
            "avatar_url": self.avatar_url,
            "state": self.state,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "is_muted": self.is_muted,
            "is_video": self.is_video,
            "is_screen_sharing": self.is_screen_sharing,
        }


@dataclass
class GroupCall:
    call_id: str
    room_id: int
    initiator_id: int
    call_type: str                  # group_audio | group_video
    state: str = "ringing"          # ringing | active | ended
    topology: str = "mesh"          # mesh | sfu
    participants: dict[int, GroupCallParticipant] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    max_participants: int = 10

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "room_id": self.room_id,
            "initiator_id": self.initiator_id,
            "call_type": self.call_type,
            "state": self.state,
            "topology": self.topology,
            "participant_count": sum(1 for p in self.participants.values() if p.state in ("connecting", "connected")),
            "participants": [p.to_dict() for p in self.participants.values()],
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
        }

    def connected_count(self) -> int:
        return sum(1 for p in self.participants.values() if p.state in ("connecting", "connected"))


_active_group_calls: dict[str, GroupCall] = {}
_room_active_call: dict[int, str] = {}


def _get_call(call_id: str) -> GroupCall:
    call = _active_group_calls.get(call_id)
    if not call or call.state == "ended":
        raise HTTPException(404, "Звонок не найден или завершён")
    return call


def _end_call(call: GroupCall) -> None:
    call.state = "ended"
    _room_active_call.pop(call.room_id, None)
    _active_group_calls.pop(call.call_id, None)


# ── Ringing timeout ─────────────────────────────────────────────────────────

RING_TIMEOUT = 30  # seconds

async def _ring_timeout(call_id: str) -> None:
    await asyncio.sleep(RING_TIMEOUT)
    call = _active_group_calls.get(call_id)
    if call and call.state == "ringing":
        logger.info("Group call %s timed out (no one joined)", call_id)
        await _broadcast_call_event(call, "group_call_ended", {"reason": "timeout"})
        _end_call(call)


async def _broadcast_call_event(call: GroupCall, event_type: str, extra: dict | None = None) -> None:
    payload = {"type": event_type, "call_id": call.call_id, "room_id": call.room_id}
    if extra:
        payload.update(extra)
    await manager.broadcast_to_room(call.room_id, payload)


# ── Request models ──────────────────────────────────────────────────────────

class StartCallRequest(BaseModel):
    call_type: str = "group_audio"


class MuteRequest(BaseModel):
    is_muted: bool = False
    is_video: bool = False


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/{room_id}/start")
async def start_group_call(
    room_id: int,
    body: StartCallRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Создать групповой звонок и уведомить всех участников комнаты."""
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(404, "Комната не найдена")

    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == u.id
    ).first()
    if not member:
        raise HTTPException(403, "Вы не участник комнаты")

    if room_id in _room_active_call:
        existing = _active_group_calls.get(_room_active_call[room_id])
        if existing and existing.state != "ended":
            return {"call_id": existing.call_id, "already_active": True}

    call_id = str(uuid.uuid4())

    # Determine topology: mesh (≤ threshold, E2E) or SFU (> threshold, scalable)
    members = db.query(RoomMember).filter(RoomMember.room_id == room_id).all()
    member_count = len(members)

    from app.chats.sfu import is_sfu_available, SFU_THRESHOLD, SFU_MAX_PARTICIPANTS
    use_sfu = is_sfu_available() and member_count > SFU_THRESHOLD
    topology = "sfu" if use_sfu else "mesh"
    max_p = SFU_MAX_PARTICIPANTS if use_sfu else 10

    call = GroupCall(
        call_id=call_id,
        room_id=room_id,
        initiator_id=u.id,
        call_type=body.call_type,
        topology=topology,
        max_participants=max_p,
    )
    for m in members:
        member_user = db.get(User, m.user_id)
        if not member_user:
            continue
        state = "connecting" if m.user_id == u.id else "invited"
        call.participants[m.user_id] = GroupCallParticipant(
            user_id=m.user_id,
            username=member_user.username,
            display_name=member_user.display_name or member_user.username,
            avatar_emoji=member_user.avatar_emoji or "\U0001f464",
            avatar_url=member_user.avatar_url,
            state=state,
            joined_at=datetime.now(timezone.utc) if state == "connecting" else None,
        )

    _active_group_calls[call_id] = call
    _room_active_call[room_id] = call_id

    # Broadcast invite to room
    await _broadcast_call_event(call, "group_call_invite", {
        "initiator": {
            "user_id": u.id,
            "username": u.username,
            "display_name": u.display_name or u.username,
            "avatar_emoji": u.avatar_emoji or "\U0001f464",
        },
        "call_type": body.call_type,
    })

    # Start ringing timeout
    asyncio.create_task(_ring_timeout(call_id))

    return {"call_id": call_id, "already_active": False, "topology": topology}


@router.post("/{call_id}/join")
async def join_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Принять приглашение и подключиться к групповому звонку."""
    call = _get_call(call_id)

    p = call.participants.get(u.id)
    if not p:
        raise HTTPException(403, "Вы не приглашены в этот звонок")

    if p.state in ("connected", "connecting"):
        return {"ok": True, "call": call.to_dict()}

    p.state = "connecting"
    p.joined_at = datetime.now(timezone.utc)

    # If 2+ connected, call becomes active
    if call.connected_count() >= 2 and call.state == "ringing":
        call.state = "active"
        call.started_at = datetime.now(timezone.utc)

    await _broadcast_call_event(call, "group_call_participant_joined", {
        "user_id": u.id,
        "username": u.username,
        "display_name": u.display_name or u.username,
        "avatar_emoji": u.avatar_emoji or "\U0001f464",
    })

    return {"ok": True, "call": call.to_dict()}


@router.post("/{call_id}/decline")
async def decline_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Отклонить приглашение на групповой звонок."""
    call = _get_call(call_id)
    p = call.participants.get(u.id)
    if p:
        p.state = "declined"
    return {"ok": True}


@router.post("/{call_id}/leave")
async def leave_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Покинуть активный групповой звонок."""
    call = _get_call(call_id)
    p = call.participants.get(u.id)
    if p:
        p.state = "left"

    await _broadcast_call_event(call, "group_call_participant_left", {
        "user_id": u.id,
    })

    # If no one connected, end the call
    if call.connected_count() == 0:
        await _broadcast_call_event(call, "group_call_ended", {"reason": "all_left"})
        _end_call(call)

    return {"ok": True}


@router.post("/{call_id}/add/{user_id}")
async def add_participant(
    call_id: str,
    user_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Добавить участника в активный звонок (mid-call invite)."""
    call = _get_call(call_id)

    if u.id not in call.participants:
        raise HTTPException(403, "Вы не участник этого звонка")

    if user_id in call.participants and call.participants[user_id].state not in ("left", "declined"):
        raise HTTPException(400, "Пользователь уже в звонке")

    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "Пользователь не найден")

    call.participants[user_id] = GroupCallParticipant(
        user_id=user_id,
        username=target_user.username,
        display_name=target_user.display_name or target_user.username,
        avatar_emoji=target_user.avatar_emoji or "\U0001f464",
        avatar_url=target_user.avatar_url,
        state="invited",
    )

    # Notify the specific user
    try:
        await manager.notify_user(user_id, {
            "type": "group_call_invite",
            "call_id": call.call_id,
            "room_id": call.room_id,
            "call_type": call.call_type,
            "initiator": {
                "user_id": u.id,
                "username": u.username,
                "display_name": u.display_name or u.username,
            },
        })
    except Exception as e:
        logger.warning("Failed to notify user %s: %s", user_id, e)

    return {"ok": True}


@router.get("/{call_id}/status")
async def get_call_status(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Получить статус группового звонка и список участников."""
    call = _get_call(call_id)
    return call.to_dict()


@router.post("/{call_id}/end")
async def end_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Завершить звонок для всех (инициатор или admin)."""
    call = _get_call(call_id)
    if u.id != call.initiator_id:
        raise HTTPException(403, "Только инициатор может завершить звонок для всех")

    await _broadcast_call_event(call, "group_call_ended", {"reason": "ended_by_initiator"})
    _end_call(call)
    return {"ok": True}


@router.get("/{room_id}/active")
async def get_active_call(
    room_id: int,
    u: User = Depends(get_current_user),
):
    """Проверить, есть ли активный звонок в комнате."""
    call_id = _room_active_call.get(room_id)
    if not call_id:
        return {"active": False}
    call = _active_group_calls.get(call_id)
    if not call or call.state == "ended":
        _room_active_call.pop(room_id, None)
        return {"active": False}
    return {"active": True, "call": call.to_dict()}
