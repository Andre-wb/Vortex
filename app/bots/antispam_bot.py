"""
app/bots/antispam_bot.py — Встроенный системный антиспам-бот.

Автоматически создаётся при первом запуске.
Добавляется/удаляется из комнат через настройки антиспама.
Отправляет сообщения о нарушениях как реальный бот-участник.

Дополнительные детекторы (помимо flood из chat.py):
  - Повторяющиеся сообщения (3+ одинаковых за 30 сек)
  - Спам ссылками (3+ сообщений с URL за 60 сек, для не-админов)
  - Caps Lock спам (>80% заглавных и >20 символов)
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import time
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import Bot, User
from app.models_rooms import (
    Message, MessageType, Room, RoomMember, RoomRole,
)
from app.peer.connection_manager import manager

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Module-level cache for fast access
# ══════════════════════════════════════════════════════════════════════════════

_antispam_bot_user_id: int | None = None
_antispam_bot_id: int | None = None

ANTISPAM_USERNAME = "antispam_bot"

# ══════════════════════════════════════════════════════════════════════════════
# Default antispam config
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_ANTISPAM_CONFIG = {
    "threshold": 15,
    "action": "mute",
    "block_repeats": True,
    "block_links": True,
}


def get_antispam_config(room: Room) -> dict:
    """Parse antispam_config JSON from room, with defaults."""
    cfg = DEFAULT_ANTISPAM_CONFIG.copy()
    raw = getattr(room, "antispam_config", None) or "{}"
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            cfg.update(parsed)
    except (json.JSONDecodeError, TypeError):
        pass
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# System bot creation / lookup
# ══════════════════════════════════════════════════════════════════════════════

def ensure_antispam_bot(db: Session) -> int:
    """
    Ensure the system antispam bot exists. Returns its user_id.
    Called once during app lifespan startup.
    """
    global _antispam_bot_user_id, _antispam_bot_id

    # Check if already exists
    bot_user = db.query(User).filter(User.username == ANTISPAM_USERNAME).first()
    if bot_user:
        _antispam_bot_user_id = bot_user.id
        bot_record = db.query(Bot).filter(Bot.user_id == bot_user.id).first()
        if bot_record:
            _antispam_bot_id = bot_record.id
        logger.info(f"Antispam bot found: user_id={bot_user.id}")
        return bot_user.id

    # Create bot user
    bot_user = User(
        phone=f"+0{secrets.token_hex(7)}",
        username=ANTISPAM_USERNAME,
        display_name="Antispam",
        avatar_emoji="\U0001f6e1\ufe0f",
        password_hash="!" + secrets.token_hex(32),
        is_bot=True,
        x25519_public_key=secrets.token_hex(32),
    )
    db.add(bot_user)
    db.flush()

    # Create bot record (owner_id = bot itself for system bots)
    from app.bots.bot_shared import _hash_token
    api_token = secrets.token_hex(32)
    bot_record = Bot(
        user_id=bot_user.id,
        owner_id=bot_user.id,
        api_token=_hash_token(api_token),
        name="Antispam",
        description="Built-in spam protection bot",
        is_active=True,
        commands=json.dumps([
            {"command": "/antispam_status", "description": "Show antispam settings"},
            {"command": "/antispam_help", "description": "Antispam bot help"},
        ]),
    )
    db.add(bot_record)
    db.commit()
    db.refresh(bot_user)
    db.refresh(bot_record)

    _antispam_bot_user_id = bot_user.id
    _antispam_bot_id = bot_record.id

    logger.info(
        f"Antispam bot CREATED: user_id={bot_user.id}, bot_id={bot_record.id}"
    )
    return bot_user.id


def get_antispam_bot_user_id() -> int | None:
    """Return cached antispam bot user_id (set during startup)."""
    return _antispam_bot_user_id


def get_antispam_bot_id() -> int | None:
    """Return cached antispam bot record id."""
    return _antispam_bot_id


# ══════════════════════════════════════════════════════════════════════════════
# Room membership management
# ══════════════════════════════════════════════════════════════════════════════

def add_antispam_bot_to_room(room_id: int, db: Session) -> bool:
    """Add antispam bot as a member of the room. Returns True if added."""
    bot_uid = get_antispam_bot_user_id()
    if not bot_uid:
        return False

    existing = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == bot_uid,
    ).first()

    if existing:
        # Un-ban if previously banned
        if existing.is_banned:
            existing.is_banned = False
            db.commit()
        return False

    db.add(RoomMember(
        room_id=room_id,
        user_id=bot_uid,
        role=RoomRole.MEMBER,
    ))
    db.commit()
    logger.info(f"Antispam bot added to room {room_id}")
    return True


def remove_antispam_bot_from_room(room_id: int, db: Session) -> bool:
    """Remove antispam bot from the room. Returns True if removed."""
    bot_uid = get_antispam_bot_user_id()
    if not bot_uid:
        return False

    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == bot_uid,
    ).first()

    if not member:
        return False

    db.delete(member)
    db.commit()
    logger.info(f"Antispam bot removed from room {room_id}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Bot message sending (internal, no API token needed)
# ══════════════════════════════════════════════════════════════════════════════

async def antispam_bot_message(room_id: int, text: str, db: Session) -> Message | None:
    """
    Send a message from the antispam bot to the room.
    Stores as plaintext (like regular bot messages) and broadcasts to all.
    """
    bot_uid = get_antispam_bot_user_id()
    bot_id = get_antispam_bot_id()
    if not bot_uid:
        return None

    # Make sure bot is actually in the room
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == bot_uid,
    ).first()
    if not member:
        return None

    bot_user = db.query(User).filter(User.id == bot_uid).first()
    if not bot_user:
        return None

    msg = Message(
        room_id=room_id,
        sender_id=bot_uid,
        msg_type=MessageType.TEXT,
        content_encrypted=text.encode("utf-8"),
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    payload = {
        "type":         "message",
        "msg_id":       msg.id,
        "sender_id":    bot_uid,
        "sender":       bot_user.username,
        "display_name": bot_user.display_name or "Antispam",
        "avatar_emoji": bot_user.avatar_emoji or "\U0001f6e1\ufe0f",
        "avatar_url":   bot_user.avatar_url,
        "is_bot":       True,
        "bot_id":       bot_id,
        "bot_name":     "Antispam",
        "plaintext":    text,
        "msg_type":     "text",
        "reply_to_id":  None,
        "status":       "sent",
        "created_at":   msg.created_at.isoformat(),
    }
    await manager.broadcast_to_room(room_id, payload)

    return msg


# ══════════════════════════════════════════════════════════════════════════════
# Enhanced spam detectors (repeat, links, caps)
# ══════════════════════════════════════════════════════════════════════════════

# "room:user" -> list of (timestamp, text_hash) for repeat detection
_repeat_tracker: dict[str, list[tuple[float, str]]] = {}

# "room:user" -> list of timestamps for link spam detection
_link_tracker: dict[str, list[float]] = {}

_REPEAT_WINDOW = 30      # seconds
_REPEAT_THRESHOLD = 3    # same message N times
_LINK_WINDOW = 60         # seconds
_LINK_THRESHOLD = 3       # messages with URLs
_CAPS_MIN_LENGTH = 20     # minimum message length for caps check
_CAPS_RATIO = 0.8         # 80% uppercase

_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)

_TRACKER_TTL = 300.0      # 5 minutes — evict stale entries
_last_cleanup: float = 0.0


def _cleanup_trackers() -> None:
    """Remove tracker entries older than _TRACKER_TTL to prevent unbounded growth."""
    global _last_cleanup
    now = time.monotonic()
    if now - _last_cleanup < 60.0:      # run at most once per minute
        return
    _last_cleanup = now

    stale_keys: list[str] = []
    for key, entries in _repeat_tracker.items():
        fresh = [(t, h) for t, h in entries if now - t < _TRACKER_TTL]
        if fresh:
            _repeat_tracker[key] = fresh
        else:
            stale_keys.append(key)
    for key in stale_keys:
        del _repeat_tracker[key]

    stale_keys.clear()
    for key, timestamps in _link_tracker.items():
        fresh = [t for t in timestamps if now - t < _TRACKER_TTL]
        if fresh:
            _link_tracker[key] = fresh
        else:
            stale_keys.append(key)
    for key in stale_keys:
        del _link_tracker[key]


async def check_repeat_spam(
    room_id: int, user: User, plaintext: str, db: Session,
) -> bool:
    """
    Check for repeated messages. Returns True if spam detected (message should be dropped).
    """
    _cleanup_trackers()
    key = f"{room_id}:{user.id}"
    now = time.monotonic()
    text_lower = plaintext.strip().lower()

    entries = _repeat_tracker.get(key, [])
    entries = [(t, h) for t, h in entries if now - t < _REPEAT_WINDOW]
    entries.append((now, text_lower))
    _repeat_tracker[key] = entries

    same_count = sum(1 for _, h in entries if h == text_lower)
    if same_count >= _REPEAT_THRESHOLD:
        _repeat_tracker[key] = []
        await antispam_bot_message(
            room_id,
            f"\u26a0\ufe0f {user.display_name or user.username}: "
            f"repeated messages blocked. "
            f"Please stop sending identical messages.",
            db,
        )
        return True
    return False


async def check_link_spam(
    room_id: int, user: User, plaintext: str, member_role: RoomRole, db: Session,
) -> bool:
    """
    Check for link spam (non-admin users only). Returns True if spam detected.
    """
    if member_role in (RoomRole.OWNER, RoomRole.ADMIN):
        return False

    if not _URL_RE.search(plaintext):
        return False

    key = f"{room_id}:{user.id}"
    now = time.monotonic()

    timestamps = _link_tracker.get(key, [])
    timestamps = [t for t in timestamps if now - t < _LINK_WINDOW]
    timestamps.append(now)
    _link_tracker[key] = timestamps

    if len(timestamps) >= _LINK_THRESHOLD:
        _link_tracker[key] = []
        await antispam_bot_message(
            room_id,
            f"\u26a0\ufe0f {user.display_name or user.username}: "
            f"too many links. "
            f"Link sending is temporarily restricted.",
            db,
        )
        return True
    return False


async def check_caps_spam(
    room_id: int, user: User, plaintext: str, db: Session,
) -> bool:
    """
    Check for caps lock spam. Returns True if spam detected.
    """
    alpha_chars = [c for c in plaintext if c.isalpha()]
    if len(alpha_chars) < _CAPS_MIN_LENGTH:
        return False

    upper_count = sum(1 for c in alpha_chars if c.isupper())
    ratio = upper_count / len(alpha_chars)

    if ratio > _CAPS_RATIO:
        await antispam_bot_message(
            room_id,
            f"\u26a0\ufe0f {user.display_name or user.username}: "
            f"please do not write in ALL CAPS.",
            db,
        )
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Bot command handlers
# ══════════════════════════════════════════════════════════════════════════════

_ACTION_LABELS = {
    "warn": "Warning",
    "mute": "Mute for 5 min",
    "kick": "Kick from room",
    "ban":  "Ban",
}

_THRESHOLD_LABELS = {
    5:  "Strict (5)",
    10: "Medium (10)",
    15: "Gentle (15)",
}


async def handle_antispam_command(
    room_id: int, command: str, db: Session,
) -> None:
    """Handle /antispam_status and /antispam_help commands."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        return

    if command == "/antispam_status":
        cfg = get_antispam_config(room)
        enabled = room.antispam_enabled if room.antispam_enabled is not None else True
        status = "\u2705 Enabled" if enabled else "\u274c Disabled"
        threshold = cfg.get("threshold", 15)
        action = cfg.get("action", "mute")
        block_repeats = cfg.get("block_repeats", True)
        block_links = cfg.get("block_links", True)

        text = (
            f"\U0001f6e1\ufe0f Antispam Settings\n"
            f"Status: {status}\n"
            f"Flood threshold: {_THRESHOLD_LABELS.get(threshold, str(threshold))} msg/10sec\n"
            f"Action: {_ACTION_LABELS.get(action, action)}\n"
            f"Block repeats: {'\u2705' if block_repeats else '\u274c'}\n"
            f"Block links: {'\u2705' if block_links else '\u274c'}"
        )
        await antispam_bot_message(room_id, text, db)

    elif command == "/antispam_help":
        text = (
            "\U0001f6e1\ufe0f Antispam Bot \u2014 Help\n\n"
            "The bot automatically protects the room from:\n"
            "\u2022 Flooding (too many messages in a short time)\n"
            "\u2022 Repeated messages\n"
            "\u2022 Link spam\n"
            "\u2022 ALL CAPS messages\n\n"
            "Commands:\n"
            "/antispam_status \u2014 current settings\n"
            "/antispam_help \u2014 this help\n\n"
            "Settings can be changed in the room info panel (owner/admin)."
        )
        await antispam_bot_message(room_id, text, db)
