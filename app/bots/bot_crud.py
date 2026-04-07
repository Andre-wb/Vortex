"""
app/bots/bot_crud.py — Bot management endpoints (for bot owners, JWT auth).

CRUD operations, token regeneration, mini-app tokens, room membership.
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Bot, User
from app.models_rooms import RoomMember, RoomRole, Room
from app.security.auth_jwt import get_current_user

from app.bots.bot_shared import (
    router,
    CreateBotRequest,
    UpdateBotRequest,
    _bot_queues_lock,
    remove_bot_queue,
    _hash_token,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Bot management endpoints (for bot owners, JWT auth)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/bots", status_code=201)
async def create_bot(
    body: CreateBotRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a new bot. Automatically creates a User account for the bot
    with is_bot=True. Returns the api_token for the bot.
    """
    # Limit: max 10 bots per user
    existing_count = db.query(Bot).filter(Bot.owner_id == user.id).count()
    if existing_count >= 10:
        raise HTTPException(400, "Maximum 10 bots per user")

    # Create bot user account
    bot_username = f"bot_{secrets.token_hex(6)}"
    bot_phone = f"+0{secrets.token_hex(7)}"  # fake phone for bot

    bot_user = User(
        phone=bot_phone,
        username=bot_username,
        display_name=body.name,
        avatar_emoji="🤖",
        password_hash="!bot_account_no_login!",  # bots can't log in via password
        is_bot=True,
        x25519_public_key=secrets.token_hex(32),  # dummy key, bots don't use E2E
    )
    db.add(bot_user)
    db.flush()  # get bot_user.id

    api_token = secrets.token_hex(32)  # 64 chars
    token_hash = _hash_token(api_token)

    bot = Bot(
        user_id=bot_user.id,
        owner_id=user.id,
        api_token=token_hash,
        name=body.name,
        description=body.description,
    )
    db.add(bot)
    db.commit()
    db.refresh(bot)

    logger.info(f"Bot created: {bot.name} (id={bot.id}) by user {user.username}")

    return {
        "ok": True,
        "bot_id": bot.id,
        "bot_user_id": bot_user.id,
        "username": bot_username,
        "name": bot.name,
        "api_token": api_token,
    }


@router.get("/api/bots")
async def list_bots(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all bots owned by the current user."""
    bots = db.query(Bot).filter(Bot.owner_id == user.id).order_by(Bot.created_at.desc()).all()
    return {
        "bots": [
            {
                "bot_id": b.id,
                "bot_user_id": b.user_id,
                "name": b.name,
                "description": b.description,
                "avatar_url": b.avatar_url,
                "is_active": b.is_active,
                "commands": json.loads(b.commands or "[]"),
                "created_at": b.created_at.isoformat() if b.created_at else "",
                "username": b.bot_user.username if b.bot_user else "",
                "mini_app_url": b.mini_app_url,
                "mini_app_enabled": b.mini_app_enabled or False,
                "is_public": b.is_public or False,
                "category": b.category or "other",
                "installs": b.installs or 0,
                "rating": round(b.rating or 0, 1),
                "rating_count": b.rating_count or 0,
            }
            for b in bots
        ]
    }


@router.put("/api/bots/{bot_id}")
async def update_bot(
    bot_id: int,
    body: UpdateBotRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update bot info and commands."""
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    if body.name is not None:
        bot.name = body.name
        # Also update display_name on the bot's User account
        bot_user = db.query(User).filter(User.id == bot.user_id).first()
        if bot_user:
            bot_user.display_name = body.name
    if body.description is not None:
        bot.description = body.description
    if body.commands is not None:
        # Validate JSON
        try:
            parsed = json.loads(body.commands)
            if not isinstance(parsed, list):
                raise ValueError
            for item in parsed:
                if not isinstance(item, dict) or "command" not in item:
                    raise ValueError
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(422, "commands must be a JSON array of {command, description}")
        bot.commands = body.commands

    if body.mini_app_url is not None:
        url = body.mini_app_url.strip()
        if url == "":
            # Clear mini app
            bot.mini_app_url = None
            bot.mini_app_enabled = False
        else:
            if not url.startswith(("https://", "http://")):
                raise HTTPException(422, "mini_app_url must start with https:// or http://")
            bot.mini_app_url = url
            bot.mini_app_enabled = True

    db.commit()
    return {"ok": True}


@router.delete("/api/bots/{bot_id}")
async def delete_bot(
    bot_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a bot and its User account."""
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    bot_user_id = bot.user_id

    # Remove bot from all rooms
    db.query(RoomMember).filter(RoomMember.user_id == bot_user_id).delete()

    # Delete bot record
    db.delete(bot)

    # Delete bot user account
    bot_user = db.query(User).filter(User.id == bot_user_id).first()
    if bot_user:
        db.delete(bot_user)

    db.commit()

    # Cleanup update queue
    async with _bot_queues_lock:
        remove_bot_queue(bot_user_id)

    logger.info(f"Bot deleted: id={bot_id} by user {user.username}")
    return {"ok": True}


@router.post("/api/bots/{bot_id}/regenerate-token")
async def regenerate_token(
    bot_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Regenerate the API token for a bot."""
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    new_token = secrets.token_hex(32)
    bot.api_token = _hash_token(new_token)
    db.commit()

    return {"ok": True, "api_token": new_token}


@router.get("/api/bots/{bot_id}/token")
async def get_bot_token(
    bot_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Token is stored as a hash and cannot be retrieved.
    Use /regenerate-token to get a new plaintext token.
    """
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")
    raise HTTPException(
        400,
        "Token is stored hashed and cannot be retrieved. "
        "Use POST /api/bots/{bot_id}/regenerate-token to generate a new one.",
    )


@router.get("/api/bots/{bot_id}/mini-app-token")
async def get_mini_app_token(
    bot_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate a short-lived JWT token for the mini app iframe.

    The mini app receives this token so it can identify the user and
    make authenticated requests back to the Vortex API if needed.
    Token is valid for 1 hour.

    Payload: {sub: user_id, username, display_name, bot_id, typ: "miniapp"}
    """
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        # Allow any user to get a mini-app token if the bot has a mini app enabled
        bot = db.query(Bot).filter(Bot.id == bot_id, Bot.mini_app_enabled == True).first()
    if not bot:
        raise HTTPException(404, "Bot not found or mini app not enabled")
    if not bot.mini_app_url or not bot.mini_app_enabled:
        raise HTTPException(400, "This bot does not have a mini app configured")

    import jwt as pyjwt
    from app.config import Config

    now = datetime.now(timezone.utc)
    payload = {
        "sub":          str(user.id),
        "username":     user.username,
        "display_name": user.display_name or user.username,
        "bot_id":       bot.id,
        "bot_name":     bot.name,
        "iat":          now,
        "exp":          now + timedelta(hours=1),
        "jti":          secrets.token_hex(16),
        "typ":          "miniapp",
    }
    token = pyjwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")

    return {
        "token": token,
        "expires_in": 3600,
        "bot_id": bot.id,
        "mini_app_url": bot.mini_app_url,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Add / remove bot from room (for bot owners, JWT auth)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/bots/{bot_id}/rooms/{room_id}")
async def add_bot_to_room(
    bot_id: int,
    room_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a bot to a room. The user must own the bot and be a member of the room."""
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    # Check user is a member of the room
    user_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
    ).first()
    if not user_member:
        raise HTTPException(403, "You are not a member of this room")

    # Check bot is not already in the room
    existing = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == bot.user_id,
    ).first()
    if existing:
        return {"ok": True, "message": "Bot is already in this room"}

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")

    db.add(RoomMember(
        room_id=room_id,
        user_id=bot.user_id,
        role=RoomRole.MEMBER,
    ))
    db.commit()

    logger.info(f"Bot {bot.name} added to room {room_id}")
    return {"ok": True}


@router.delete("/api/bots/{bot_id}/rooms/{room_id}")
async def remove_bot_from_room(
    bot_id: int,
    room_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove a bot from a room."""
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    deleted = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == bot.user_id,
    ).delete()
    db.commit()

    if not deleted:
        raise HTTPException(404, "Bot is not in this room")

    return {"ok": True}
