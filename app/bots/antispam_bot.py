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
        display_name="\u0410\u043d\u0442\u0438\u0441\u043f\u0430\u043c",
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
        name="\u0410\u043d\u0442\u0438\u0441\u043f\u0430\u043c",
        description="\u0412\u0441\u0442\u0440\u043e\u0435\u043d\u043d\u044b\u0439 \u0431\u043e\u0442 \u0437\u0430\u0449\u0438\u0442\u044b \u043e\u0442 \u0441\u043f\u0430\u043c\u0430",
        is_active=True,
        commands=json.dumps([
            {"command": "/antispam_status", "description": "\u041f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u0430\u043d\u0442\u0438\u0441\u043f\u0430\u043c\u0430"},
            {"command": "/antispam_help", "description": "\u041f\u043e\u043c\u043e\u0449\u044c \u043f\u043e \u0430\u043d\u0442\u0438\u0441\u043f\u0430\u043c-\u0431\u043e\u0442\u0443"},
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
        "display_name": bot_user.display_name or "\u0410\u043d\u0442\u0438\u0441\u043f\u0430\u043c",
        "avatar_emoji": bot_user.avatar_emoji or "\U0001f6e1\ufe0f",
        "avatar_url":   bot_user.avatar_url,
        "is_bot":       True,
        "bot_id":       bot_id,
        "bot_name":     "\u0410\u043d\u0442\u0438\u0441\u043f\u0430\u043c",
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
            f"\u043f\u043e\u0432\u0442\u043e\u0440\u044f\u044e\u0449\u0438\u0435\u0441\u044f \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u044f \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d\u044b. "
            f"\u041f\u0440\u0435\u043a\u0440\u0430\u0442\u0438\u0442\u0435 \u043e\u0442\u043f\u0440\u0430\u0432\u043a\u0443 \u043e\u0434\u0438\u043d\u0430\u043a\u043e\u0432\u044b\u0445 \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0439.",
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
            f"\u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u0441\u0441\u044b\u043b\u043e\u043a. "
            f"\u041e\u0442\u043f\u0440\u0430\u0432\u043a\u0430 \u0441\u0441\u044b\u043b\u043e\u043a \u0432\u0440\u0435\u043c\u0435\u043d\u043d\u043e \u043e\u0433\u0440\u0430\u043d\u0438\u0447\u0435\u043d\u0430.",
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
            f"\u043f\u043e\u0436\u0430\u043b\u0443\u0439\u0441\u0442\u0430, \u043d\u0435 \u043f\u0438\u0448\u0438\u0442\u0435 \u0412\u0421\u0415\u041c\u0418 \u0417\u0410\u0413\u041b\u0410\u0412\u041d\u042b\u041c\u0418 \u0431\u0443\u043a\u0432\u0430\u043c\u0438.",
            db,
        )
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Bot command handlers
# ══════════════════════════════════════════════════════════════════════════════

_ACTION_LABELS = {
    "warn": "\u041f\u0440\u0435\u0434\u0443\u043f\u0440\u0435\u0434\u0438\u0442\u044c",
    "mute": "\u0417\u0430\u0433\u043b\u0443\u0448\u0438\u0442\u044c \u043d\u0430 5 \u043c\u0438\u043d",
    "kick": "\u0418\u0441\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u0438\u0437 \u043a\u043e\u043c\u043d\u0430\u0442\u044b",
    "ban":  "\u0417\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u0442\u044c",
}

_THRESHOLD_LABELS = {
    5:  "\u0421\u0442\u0440\u043e\u0433\u0438\u0439 (5)",
    10: "\u0421\u0440\u0435\u0434\u043d\u0438\u0439 (10)",
    15: "\u041c\u044f\u0433\u043a\u0438\u0439 (15)",
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
        status = "\u2705 \u0412\u043a\u043b\u044e\u0447\u0435\u043d" if enabled else "\u274c \u0412\u044b\u043a\u043b\u044e\u0447\u0435\u043d"
        threshold = cfg.get("threshold", 15)
        action = cfg.get("action", "mute")
        block_repeats = cfg.get("block_repeats", True)
        block_links = cfg.get("block_links", True)

        text = (
            f"\U0001f6e1\ufe0f \u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u0430\u043d\u0442\u0438\u0441\u043f\u0430\u043c\u0430\n"
            f"\u0421\u0442\u0430\u0442\u0443\u0441: {status}\n"
            f"\u041f\u043e\u0440\u043e\u0433 \u0444\u043b\u0443\u0434\u0430: {_THRESHOLD_LABELS.get(threshold, str(threshold))} \u0441\u043e\u043e\u0431\u0449./10\u0441\u0435\u043a\n"
            f"\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u0435: {_ACTION_LABELS.get(action, action)}\n"
            f"\u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430 \u043f\u043e\u0432\u0442\u043e\u0440\u043e\u0432: {'\u2705' if block_repeats else '\u274c'}\n"
            f"\u0411\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430 \u0441\u0441\u044b\u043b\u043e\u043a: {'\u2705' if block_links else '\u274c'}"
        )
        await antispam_bot_message(room_id, text, db)

    elif command == "/antispam_help":
        text = (
            "\U0001f6e1\ufe0f \u0410\u043d\u0442\u0438\u0441\u043f\u0430\u043c-\u0431\u043e\u0442 \u2014 \u043f\u043e\u043c\u043e\u0449\u044c\n\n"
            "\u0411\u043e\u0442 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043a\u043e\u043c\u043d\u0430\u0442\u0443 \u043e\u0442:\n"
            "\u2022 \u0424\u043b\u0443\u0434\u0430 (\u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0439 \u0437\u0430 \u043a\u043e\u0440\u043e\u0442\u043a\u043e\u0435 \u0432\u0440\u0435\u043c\u044f)\n"
            "\u2022 \u041f\u043e\u0432\u0442\u043e\u0440\u044f\u044e\u0449\u0438\u0445\u0441\u044f \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0439\n"
            "\u2022 \u0421\u043f\u0430\u043c\u0430 \u0441\u0441\u044b\u043b\u043a\u0430\u043c\u0438\n"
            "\u2022 \u041f\u0438\u0441\u044c\u043c\u0430 \u0412\u0421\u0415\u041c\u0418 \u0417\u0410\u0413\u041b\u0410\u0412\u041d\u042b\u041c\u0418\n\n"
            "\u041a\u043e\u043c\u0430\u043d\u0434\u044b:\n"
            "/antispam_status \u2014 \u0442\u0435\u043a\u0443\u0449\u0438\u0435 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438\n"
            "/antispam_help \u2014 \u044d\u0442\u0430 \u0441\u043f\u0440\u0430\u0432\u043a\u0430\n\n"
            "\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u043c\u0435\u043d\u044f\u044e\u0442\u0441\u044f \u0432 \u043f\u0430\u043d\u0435\u043b\u0438 \u0438\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u0438 \u043a\u043e\u043c\u043d\u0430\u0442\u044b (owner/admin)."
        )
        await antispam_bot_message(room_id, text, db)
