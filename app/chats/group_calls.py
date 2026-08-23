"""
app/chats/group_calls.py — Ad-hoc group calls with invite/accept/decline lifecycle.

Unlike voice channels (persistent, join-anytime), group calls are initiated
by a user, ring for all room members, and end when everyone leaves or the
initiator ends the call.  Запись о звонке живёт в общем сторе
(`vortex-live` через `app.chats.live_backend`) и видна всем воркерам.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.chats import live_backend as _live
from app.database import get_db
from app.models import User
from app.models_rooms import Room, RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.utilites.background import spawn

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/group-calls", tags=["group-calls"])

RING_TIMEOUT = 30  # seconds


def _require_call(call: Optional[dict]) -> dict:
    if not call:
        raise HTTPException(404, "Call not found or ended")
    return call


async def _ring_timeout(call_id: str) -> None:
    await asyncio.sleep(RING_TIMEOUT)
    with contextlib.suppress(_live.LiveUnavailableError):
        rung = _live.call_ring_out(call_id)
        if rung:
            logger.info("Group call %s timed out (no one joined)", call_id)
            await _broadcast_call_event(rung, "group_call_ended", {"reason": "timeout"})


async def _broadcast_call_event(call: dict, event_type: str, extra: dict | None = None) -> None:
    payload = {"type": event_type, "call_id": call["call_id"], "room_id": call["room_id"]}
    if extra:
        payload.update(extra)
    await manager.broadcast_to_room(call["room_id"], payload)


class StartCallRequest(BaseModel):
    call_type: str = "group_audio"


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
        raise HTTPException(404, "Room not found")

    member = db.query(RoomMember).filter(RoomMember.room_id == room_id, RoomMember.user_id == u.id).first()
    if not member:
        raise HTTPException(403, "You are not a room member")

    members = db.query(RoomMember).filter(RoomMember.room_id == room_id).limit(500).all()
    seated = []
    for m in members:
        member_user = db.get(User, m.user_id)
        if not member_user:
            continue
        seated.append(_live.identity_of(member_user))

    from app.chats.sfu import SFU_MAX_PARTICIPANTS, SFU_THRESHOLD, is_sfu_available

    started = _live.call_start(
        room_id,
        u.id,
        body.call_type,
        seated,
        is_sfu_available(),
        SFU_THRESHOLD,
        SFU_MAX_PARTICIPANTS,
    )
    if started["already_active"]:
        return {"call_id": started["call_id"], "already_active": True}

    call = started["call"]

    # Broadcast invite to room
    await _broadcast_call_event(
        call,
        "group_call_invite",
        {
            "initiator": {
                "user_id": u.id,
                "username": u.username,
                "display_name": u.display_name or u.username,
                "avatar_emoji": u.avatar_emoji or "\U0001f464",
            },
            "call_type": body.call_type,
        },
    )

    # Start ringing timeout
    spawn(_ring_timeout(call["call_id"]))

    return {
        "call_id": call["call_id"],
        "already_active": False,
        "topology": started["topology"],
    }


@router.post("/{call_id}/join")
async def join_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Принять приглашение и подключиться к групповому звонку."""
    joined = _live.call_join(call_id, u.id)
    if joined["status"] == "missing":
        raise HTTPException(404, "Call not found or ended")
    if joined["status"] == "not_invited":
        raise HTTPException(403, "You are not invited to this call")

    call = joined["call"]
    await _broadcast_call_event(
        call,
        "group_call_participant_joined",
        {
            "user_id": u.id,
            "username": u.username,
            "display_name": u.display_name or u.username,
            "avatar_emoji": u.avatar_emoji or "\U0001f464",
        },
    )

    return {"ok": True, "call": call}


@router.post("/{call_id}/decline")
async def decline_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Отклонить приглашение на групповой звонок."""
    if _live.call_decline(call_id, u.id) == "missing":
        raise HTTPException(404, "Call not found or ended")
    return {"ok": True}


@router.post("/{call_id}/leave")
async def leave_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Покинуть активный групповой звонок."""
    left = _live.call_leave(call_id, u.id)
    if left["status"] == "missing":
        raise HTTPException(404, "Call not found or ended")

    call = left["call"]
    await _broadcast_call_event(
        call,
        "group_call_participant_left",
        {
            "user_id": u.id,
        },
    )

    if left["ended"]:
        await _broadcast_call_event(call, "group_call_ended", {"reason": "all_left"})

    return {"ok": True}


@router.post("/{call_id}/add/{user_id}")
async def add_participant(
    call_id: str,
    user_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Добавить участника в активный звонок (mid-call invite)."""
    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")

    added = _live.call_add(call_id, u.id, target_user)
    if added["status"] == "missing":
        raise HTTPException(404, "Call not found or ended")
    if added["status"] == "not_a_participant":
        raise HTTPException(403, "You are not a participant in this call")
    if added["status"] == "already_in":
        raise HTTPException(400, "User is already in the call")

    call = added["call"]

    # BMP mode: group call invite goes through BMP room deposit
    from app.config import Config

    if Config.BMP_DELIVERY_ENABLED:
        with contextlib.suppress(Exception):
            import json

            from app.transport.blind_mailbox import deposit_envelope

            await deposit_envelope(
                call["room_id"],
                json.dumps(
                    {
                        "type": "group_call_invite",
                        "call_id": call["call_id"],
                        "room_id": call["room_id"],
                        "call_type": call["call_type"],
                    }
                ),
            )
    else:
        with contextlib.suppress(Exception):
            await manager.notify_user(
                user_id,
                {
                    "type": "group_call_invite",
                    "call_id": call["call_id"],
                    "room_id": call["room_id"],
                    "call_type": call["call_type"],
                    "initiator": {
                        "user_id": u.id,
                        "username": u.username,
                        "display_name": u.display_name or u.username,
                    },
                },
            )

    return {"ok": True}


@router.get("/{call_id}/status")
async def get_call_status(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Получить статус группового звонка и список участников."""
    return _require_call(_live.call_status(call_id))


@router.post("/{call_id}/end")
async def end_group_call(
    call_id: str,
    u: User = Depends(get_current_user),
):
    """Завершить звонок для всех (инициатор или admin)."""
    ended = _live.call_end(call_id, u.id)
    if ended["status"] == "missing":
        raise HTTPException(404, "Call not found or ended")
    if ended["status"] == "not_initiator":
        raise HTTPException(403, "Only the initiator can end the call for everyone")

    await _broadcast_call_event(ended["call"], "group_call_ended", {"reason": "ended_by_initiator"})
    return {"ok": True}


@router.get("/{room_id}/active")
async def get_active_call(
    room_id: int,
    u: User = Depends(get_current_user),
):
    """Проверить, есть ли активный звонок в комнате."""
    call = _live.call_active(room_id)
    if not call:
        return {"active": False}
    return {"active": True, "call": call}
