"""
app/bots/bot_marketplace.py — Bot Marketplace endpoints (JWT auth).

Publishing, browsing, searching, reviews, and installing public bots.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Bot, BotReview, User
from app.models_rooms import RoomMember, Room, RoomRole
from app.security.auth_jwt import get_current_user

from app.bots.bot_shared import (
    router,
    PublishBotRequest,
    SubmitReviewRequest,
    MARKETPLACE_CATEGORIES,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Bot Marketplace: publish toggle (owner only)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/bots/{bot_id}/publish")
async def publish_bot(
    bot_id: int,
    body: PublishBotRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Make bot public/private in marketplace. Owner only."""
    bot = db.query(Bot).filter(Bot.id == bot_id, Bot.owner_id == user.id).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    cat = body.category.lower().strip()
    if cat not in MARKETPLACE_CATEGORIES:
        cat = "other"

    bot.is_public = body.is_public
    bot.category = cat
    db.commit()

    return {"ok": True, "is_public": bot.is_public, "category": bot.category}


# ══════════════════════════════════════════════════════════════════════════════
# Bot Marketplace: browsing endpoints (JWT auth)
# ══════════════════════════════════════════════════════════════════════════════

def _serialize_bot_card(b: Bot) -> dict:
    """Serialize a Bot to a marketplace card dict."""
    return {
        "bot_id": b.id,
        "name": b.name,
        "description": b.description or "",
        "avatar_url": b.avatar_url,
        "category": b.category or "other",
        "installs": b.installs or 0,
        "rating": round(b.rating or 0, 1),
        "rating_count": b.rating_count or 0,
        "commands": json.loads(b.commands or "[]"),
        "owner_name": b.owner.display_name or b.owner.username if b.owner else "",
        "mini_app_url": b.mini_app_url if b.mini_app_enabled else None,
        "created_at": b.created_at.isoformat() if b.created_at else "",
    }


@router.get("/api/marketplace/categories")
async def marketplace_categories(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List categories with bot counts."""
    counts_raw = (
        db.query(Bot.category, func.count(Bot.id))
        .filter(Bot.is_public == True, Bot.is_active == True)
        .group_by(Bot.category)
        .all()
    )
    counts = {cat: cnt for cat, cnt in counts_raw}
    result = []
    for cat in MARKETPLACE_CATEGORIES:
        result.append({"id": cat, "count": counts.get(cat, 0)})
    total = sum(c["count"] for c in result)
    return {"categories": result, "total": total}


@router.get("/api/marketplace/search")
async def marketplace_search(
    q: str = Query("", max_length=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search public bots by name or description."""
    term = q.strip()
    if not term:
        return {"bots": []}
    pattern = f"%{term}%"
    bots = (
        db.query(Bot)
        .filter(
            Bot.is_public == True,
            Bot.is_active == True,
            (Bot.name.ilike(pattern) | Bot.description.ilike(pattern)),
        )
        .order_by(Bot.rating.desc(), Bot.installs.desc())
        .limit(50)
        .all()
    )
    return {"bots": [_serialize_bot_card(b) for b in bots]}


@router.get("/api/marketplace/{bot_id}")
async def marketplace_bot_detail(
    bot_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get full detail for a marketplace bot."""
    bot = db.query(Bot).filter(
        Bot.id == bot_id, Bot.is_public == True, Bot.is_active == True
    ).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    # Check if the current user already reviewed
    existing_review = db.query(BotReview).filter(
        BotReview.bot_id == bot_id, BotReview.user_id == user.id
    ).first()

    card = _serialize_bot_card(bot)
    card["user_review"] = {
        "rating": existing_review.rating,
        "text": existing_review.text or "",
    } if existing_review else None

    return card


@router.get("/api/marketplace")
async def marketplace_list(
    category: str = Query("", max_length=30),
    sort: str = Query("rating", max_length=20),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=50),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List public bots, filterable by category, sortable."""
    q = db.query(Bot).filter(Bot.is_public == True, Bot.is_active == True)

    cat = category.strip().lower()
    if cat and cat in MARKETPLACE_CATEGORIES:
        q = q.filter(Bot.category == cat)

    if sort == "installs":
        q = q.order_by(Bot.installs.desc(), Bot.rating.desc())
    elif sort == "newest":
        q = q.order_by(Bot.created_at.desc())
    else:  # default: rating
        q = q.order_by(Bot.rating.desc(), Bot.installs.desc())

    total = q.count()
    bots = q.offset(offset).limit(limit).all()

    return {
        "bots": [_serialize_bot_card(b) for b in bots],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Bot Marketplace: reviews
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/marketplace/{bot_id}/reviews")
async def marketplace_reviews(
    bot_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=50),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List reviews for a bot."""
    bot = db.query(Bot).filter(
        Bot.id == bot_id, Bot.is_public == True, Bot.is_active == True
    ).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    reviews = (
        db.query(BotReview)
        .filter(BotReview.bot_id == bot_id)
        .order_by(BotReview.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    result = []
    for r in reviews:
        reviewer = db.query(User).filter(User.id == r.user_id).first()
        result.append({
            "id": r.id,
            "rating": r.rating,
            "text": r.text or "",
            "user_id": r.user_id,
            "username": reviewer.username if reviewer else "",
            "display_name": reviewer.display_name or reviewer.username if reviewer else "",
            "avatar_emoji": reviewer.avatar_emoji if reviewer else "",
            "avatar_url": reviewer.avatar_url if reviewer else None,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        })
    return {"reviews": result}


@router.post("/api/marketplace/{bot_id}/review")
async def submit_review(
    bot_id: int,
    body: SubmitReviewRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Submit or update a review for a marketplace bot."""
    bot = db.query(Bot).filter(
        Bot.id == bot_id, Bot.is_public == True, Bot.is_active == True
    ).first()
    if not bot:
        raise HTTPException(404, "Bot not found")

    # Bot owner cannot review their own bot
    if bot.owner_id == user.id:
        raise HTTPException(400, "Cannot review your own bot")

    existing = db.query(BotReview).filter(
        BotReview.bot_id == bot_id, BotReview.user_id == user.id
    ).first()

    if existing:
        existing.rating = body.rating
        existing.text = body.text
        existing.created_at = datetime.now(timezone.utc)
    else:
        db.add(BotReview(
            bot_id=bot_id,
            user_id=user.id,
            rating=body.rating,
            text=body.text,
        ))

    db.flush()

    # Recalculate bot rating
    stats = db.query(
        func.avg(BotReview.rating),
        func.count(BotReview.id),
    ).filter(BotReview.bot_id == bot_id).first()

    bot.rating = round(float(stats[0] or 0), 2)
    bot.rating_count = stats[1] or 0
    db.commit()

    return {
        "ok": True,
        "rating": bot.rating,
        "rating_count": bot.rating_count,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Bot Marketplace: install (add public bot to room)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/marketplace/{bot_id}/install/{room_id}")
async def marketplace_install(
    bot_id: int,
    room_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Install a public marketplace bot into a user's room."""
    bot = db.query(Bot).filter(
        Bot.id == bot_id, Bot.is_public == True, Bot.is_active == True
    ).first()
    if not bot:
        raise HTTPException(404, "Bot not found in marketplace")

    # Check user is a member of the room
    user_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
    ).first()
    if not user_member:
        raise HTTPException(403, "You are not a member of this room")

    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")

    # Check bot is not already in the room
    existing = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == bot.user_id,
    ).first()
    if existing:
        return {"ok": True, "message": "Bot is already in this room"}

    db.add(RoomMember(
        room_id=room_id,
        user_id=bot.user_id,
        role=RoomRole.MEMBER,
    ))
    bot.installs = (bot.installs or 0) + 1
    db.commit()

    logger.info(f"Marketplace: bot {bot.name} installed to room {room_id} by {user.username}")
    return {"ok": True}
