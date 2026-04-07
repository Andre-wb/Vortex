"""
app/bots/bot_shared.py — Shared dependencies for the bot subsystem.

Contains: router, auth dependency, in-memory update queues, Pydantic schemas,
and constants reused across bot_crud, bot_messaging, and bot_marketplace.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Bot

logger = logging.getLogger(__name__)


def _hash_token(token: str) -> str:
    """SHA-256 hash of a bot API token."""
    return hashlib.sha256(token.encode()).hexdigest()

# ══════════════════════════════════════════════════════════════════════════════
# Router
# ══════════════════════════════════════════════════════════════════════════════

router = APIRouter(tags=["bots"])


# ══════════════════════════════════════════════════════════════════════════════
# Dependency: authenticate bot by api_token in Authorization header
# ══════════════════════════════════════════════════════════════════════════════

def _get_bot_by_token(request: Request, db: Session = Depends(get_db)) -> Bot:
    """
    Extracts bot api_token from Authorization header (Bot <token>)
    and returns the Bot object. Used for bot-side API endpoints.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bot "):
        raise HTTPException(401, "Missing or invalid Authorization header. Expected: Bot <api_token>")
    token = auth[4:].strip()
    if not token:
        raise HTTPException(401, "Empty API token")

    token_hash = _hash_token(token)
    bot = db.query(Bot).filter(Bot.api_token == token_hash, Bot.is_active == True).first()
    if not bot:
        # Fallback: try plaintext match and migrate to hashed token
        bot = db.query(Bot).filter(Bot.api_token == token, Bot.is_active == True).first()
        if bot:
            bot.api_token = token_hash
            db.commit()
    if not bot:
        raise HTTPException(401, "Invalid or inactive bot token")
    return bot


# ══════════════════════════════════════════════════════════════════════════════
# In-memory update queues for bot long-polling / WebSocket
# ══════════════════════════════════════════════════════════════════════════════

# bot_user_id -> asyncio.Queue of update dicts
_bot_queues: dict[int, asyncio.Queue] = {}
_bot_queues_lock = asyncio.Lock()


async def _get_or_create_queue(bot_user_id: int) -> asyncio.Queue:
    async with _bot_queues_lock:
        if bot_user_id not in _bot_queues:
            _bot_queues[bot_user_id] = asyncio.Queue(maxsize=1000)
        return _bot_queues[bot_user_id]


async def enqueue_bot_update(bot_user_id: int, update: dict) -> None:
    """
    Called from chat.py when a message arrives in a room where a bot is a member.
    Pushes the update into the bot's queue for delivery via long-poll or WebSocket.
    """
    async with _bot_queues_lock:
        q = _bot_queues.get(bot_user_id)
    if q:
        try:
            q.put_nowait(update)
        except asyncio.QueueFull:
            # Drop oldest to make room for the new update
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                q.put_nowait(update)
            except asyncio.QueueFull:
                logger.warning("Bot queue full for bot_user_id=%s, update dropped: %s", bot_user_id, update.get("type"))


def remove_bot_queue(bot_user_id: int) -> None:
    """Remove a bot's update queue (used on bot deletion). Must be called inside _bot_queues_lock."""
    _bot_queues.pop(bot_user_id, None)


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════════════════════════

class CreateBotRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    description: str = Field("", max_length=500)

class UpdateBotRequest(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=50)
    description: str | None = Field(None, max_length=500)
    commands: str | None = Field(None, max_length=2000)  # JSON string: [{"command":"/help","description":"..."}]
    mini_app_url: str | None = Field(None, max_length=500)  # URL of the mini app (https:// or http://)

class PublishBotRequest(BaseModel):
    is_public: bool = True
    category: str = Field("other", max_length=30)

class SubmitReviewRequest(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    text: str = Field("", max_length=500)

# Predefined marketplace categories
MARKETPLACE_CATEGORIES = [
    "utilities", "games", "moderation", "music",
    "productivity", "social", "fun", "other",
]

class BotSendRequest(BaseModel):
    room_id: int
    text: str = Field(..., min_length=1, max_length=4000)

class BotReplyRequest(BaseModel):
    room_id: int
    reply_to_id: int
    text: str = Field(..., min_length=1, max_length=4000)
