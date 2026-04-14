"""
app/chats/chat_flood.py — Flood detection: auto-mute / auto-ban.

Extracted from chat.py for maintainability.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import User
from app.models_rooms import Room, RoomMember, RoomRole
from app.peer.connection_manager import manager

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════
_FLOOD_WINDOW      = 10       # seconds
_FLOOD_THRESHOLD   = 15       # messages in window → auto-mute
_FLOOD_MUTE_SECS   = 5 * 60  # 5 minutes
_FLOOD_BAN_STRIKES = 3        # mute this many times → auto-ban

# "room:user" → list of timestamps (recent message times)
_flood_tracker: dict[str, list[float]] = {}
# "room:user" → cumulative mute count
_flood_strikes: dict[str, int] = {}
# Lock to protect concurrent access to _flood_tracker / _flood_strikes
_flood_lock: asyncio.Lock = asyncio.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# Flood checker
# ══════════════════════════════════════════════════════════════════════════════

async def check_flood(room_id: int, user: User, db: Session, threshold_override: int | None = None) -> bool:
    """Check flood threshold. Returns True if user is flooding and message should be dropped."""
    from app.bots.antispam_bot import antispam_bot_message, get_antispam_config, get_antispam_bot_user_id

    # Skip flood check for room owners and admins
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
    ).first()
    if member and member.role in (RoomRole.OWNER, RoomRole.ADMIN):
        return False

    key = f"{room_id}:{user.id}"
    now = time.monotonic()

    async with _flood_lock:
        # Prune old timestamps outside the window
        timestamps = _flood_tracker.get(key, [])
        timestamps = [t for t in timestamps if now - t < _FLOOD_WINDOW]
        timestamps.append(now)
        _flood_tracker[key] = timestamps

        # Use configurable threshold from room settings
        effective_threshold = threshold_override or _FLOOD_THRESHOLD
        if len(timestamps) <= effective_threshold:
            return False

        # ── Flood detected ────────────────────────────────────────────────────
        strikes = _flood_strikes.get(key, 0) + 1
        _flood_strikes[key] = strikes

    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
    ).first()
    if not member:
        return True

    # Determine action from room config
    room_obj = db.query(Room).filter(Room.id == room_id).first()
    cfg = get_antispam_config(room_obj) if room_obj else {}
    action = cfg.get("action", "mute")

    # On repeated strikes, escalate regardless of configured action
    if strikes >= _FLOOD_BAN_STRIKES:
        action = "ban"

    display = user.display_name or user.username
    bot_uid = get_antispam_bot_user_id()

    if action == "ban":
        member.is_banned = True
        db.commit()
        if bot_uid:
            await antispam_bot_message(
                room_id,
                f"\u26a0\ufe0f {display} \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d \u0437\u0430 \u0441\u0438\u0441\u0442\u0435\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0444\u043b\u0443\u0434",
                db,
            )
        else:
            await manager.broadcast_to_room(room_id, {
                "type":    "system",
                "message": f"\u26a0\ufe0f {display} \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d \u0437\u0430 \u0441\u0438\u0441\u0442\u0435\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0444\u043b\u0443\u0434",
            })
        await manager.send_to_user(room_id, user.id, {
            "type":    "error",
            "message": "\u0412\u044b \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d\u044b \u0432 \u044d\u0442\u043e\u0439 \u043a\u043e\u043c\u043d\u0430\u0442\u0435 \u0437\u0430 \u0444\u043b\u0443\u0434.",
            "code":    "flood_banned",
        })
        logger.warning(f"Flood auto-BAN: user={user.username} room={room_id} strikes={strikes}")

    elif action == "kick":
        member.is_banned = True
        db.commit()
        if bot_uid:
            await antispam_bot_message(
                room_id,
                f"\u26a0\ufe0f {display} \u0438\u0441\u043a\u043b\u044e\u0447\u0451\u043d \u0438\u0437 \u043a\u043e\u043c\u043d\u0430\u0442\u044b \u0437\u0430 \u0444\u043b\u0443\u0434",
                db,
            )
        await manager.send_to_user(room_id, user.id, {"type": "kicked"})
        logger.warning(f"Flood auto-KICK: user={user.username} room={room_id} strikes={strikes}")

    elif action == "warn":
        if bot_uid:
            await antispam_bot_message(
                room_id,
                f"\u26a0\ufe0f {display}, \u0432\u044b \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u0435\u0442\u0435 \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u044f \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u0431\u044b\u0441\u0442\u0440\u043e. \u041f\u043e\u0436\u0430\u043b\u0443\u0439\u0441\u0442\u0430, \u043f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435.",
                db,
            )
        await manager.send_to_user(room_id, user.id, {
            "type":    "error",
            "message": "\u0421\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0439. \u041f\u043e\u0436\u0430\u043b\u0443\u0439\u0441\u0442\u0430, \u043f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435.",
            "code":    "flood_warned",
        })
        logger.warning(f"Flood WARN: user={user.username} room={room_id} strikes={strikes}")

    else:  # default: mute
        member.muted_until = datetime.now(timezone.utc) + timedelta(seconds=_FLOOD_MUTE_SECS)
        db.commit()
        if bot_uid:
            await antispam_bot_message(
                room_id,
                f"\u26a0\ufe0f {display} \u0437\u0430\u0433\u043b\u0443\u0448\u0451\u043d \u0437\u0430 \u0444\u043b\u0443\u0434 \u043d\u0430 5 \u043c\u0438\u043d\u0443\u0442",
                db,
            )
        else:
            await manager.broadcast_to_room(room_id, {
                "type":    "system",
                "message": f"\u26a0\ufe0f {display} \u0437\u0430\u0433\u043b\u0443\u0448\u0451\u043d \u0437\u0430 \u0444\u043b\u0443\u0434 \u043d\u0430 5 \u043c\u0438\u043d\u0443\u0442",
            })
        await manager.send_to_user(room_id, user.id, {
            "type":    "error",
            "message": "\u0412\u044b \u0437\u0430\u0433\u043b\u0443\u0448\u0435\u043d\u044b \u043d\u0430 5 \u043c\u0438\u043d\u0443\u0442 \u0437\u0430 \u0444\u043b\u0443\u0434.",
            "code":    "flood_muted",
        })
        logger.warning(f"Flood auto-MUTE: user={user.username} room={room_id} strikes={strikes}")

    # Reset timestamps after penalty
    async with _flood_lock:
        _flood_tracker[key] = []
    return True
