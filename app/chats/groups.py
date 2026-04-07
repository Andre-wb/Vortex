"""
Advanced Group Features — Topics, Forum Threads, Permissions, Auto-Moderation, Per-User Slowmode.

Endpoints:
  Topics:      CRUD /api/rooms/{room_id}/topics
  Forums:      CRUD /api/rooms/{room_id}/forum
  Permissions: GET/PUT /api/rooms/{room_id}/permissions
  AutoMod:     CRUD /api/rooms/{room_id}/automod
  Slowmode:    GET/PUT /api/rooms/{room_id}/slowmode/users
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import (
    AutoModRule, ForumThread, Permission, PermissionFlags,
    Room, RoomMember, RoomRole, Topic, UserSlowmode,
)
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/rooms", tags=["groups"])


# ── Pydantic Schemas ─────────────────────────────────────────────────────────

class TopicCreate(BaseModel):
    title: str = Field(..., max_length=200)
    icon_emoji: str = Field(default="💬", max_length=10)

class TopicUpdate(BaseModel):
    title: str | None = None
    icon_emoji: str | None = None
    is_pinned: bool | None = None
    is_closed: bool | None = None

class ForumThreadCreate(BaseModel):
    title: str = Field(..., max_length=300)
    body: str = Field(default="", max_length=10000)
    tags: list[str] = Field(default_factory=list)

class ForumThreadUpdate(BaseModel):
    title: str | None = None
    is_pinned: bool | None = None
    is_locked: bool | None = None
    is_solved: bool | None = None
    tags: list[str] | None = None

class PermissionUpdate(BaseModel):
    role: str | None = None
    user_id: int | None = None
    allow: int = 0
    deny: int = 0

class AutoModRuleCreate(BaseModel):
    name: str = Field(..., max_length=100)
    rule_type: str = Field(default="word_filter")  # regex, word_filter, link_whitelist, spam_detection, caps_filter
    pattern: str = Field(..., max_length=5000)
    action: str = Field(default="delete")  # warn, delete, mute, kick, ban
    mute_duration_seconds: int = Field(default=300)

class AutoModRuleUpdate(BaseModel):
    name: str | None = None
    is_enabled: bool | None = None
    pattern: str | None = None
    action: str | None = None

class UserSlowmodeSet(BaseModel):
    user_id: int
    cooldown_seconds: int = Field(default=30, ge=0, le=3600)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
    ).first()
    if not m:
        raise HTTPException(403, "Not a member of this room")
    return m

def _require_admin(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = _require_member(room_id, user_id, db)
    if m.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Admin or owner required")
    return m


# ══════════════════════════════════════════════════════════════════════════════
# Topics
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/topics")
async def list_topics(room_id: int, u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    topics = db.query(Topic).filter(Topic.room_id == room_id).order_by(
        Topic.is_pinned.desc(), Topic.last_message_at.desc().nullslast()
    ).all()
    return {"topics": [
        {"id": t.id, "title": t.title, "icon_emoji": t.icon_emoji,
         "is_pinned": t.is_pinned, "is_closed": t.is_closed,
         "message_count": t.message_count, "created_at": t.created_at.isoformat() if t.created_at else ""}
        for t in topics
    ]}

@router.post("/{room_id}/topics", status_code=201)
async def create_topic(room_id: int, body: TopicCreate,
                       u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    t = Topic(room_id=room_id, title=body.title, icon_emoji=body.icon_emoji, creator_id=u.id)
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"id": t.id, "title": t.title, "icon_emoji": t.icon_emoji}

@router.put("/{room_id}/topics/{topic_id}")
async def update_topic(room_id: int, topic_id: int, body: TopicUpdate,
                       u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    t = db.query(Topic).filter(Topic.id == topic_id, Topic.room_id == room_id).first()
    if not t:
        raise HTTPException(404, "Topic not found")
    if body.title is not None: t.title = body.title
    if body.icon_emoji is not None: t.icon_emoji = body.icon_emoji
    if body.is_pinned is not None: t.is_pinned = body.is_pinned
    if body.is_closed is not None: t.is_closed = body.is_closed
    db.commit()
    return {"ok": True}

@router.delete("/{room_id}/topics/{topic_id}")
async def delete_topic(room_id: int, topic_id: int,
                       u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    t = db.query(Topic).filter(Topic.id == topic_id, Topic.room_id == room_id).first()
    if not t:
        raise HTTPException(404, "Topic not found")
    db.delete(t)
    db.commit()
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Forum Threads
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/forum")
async def list_forum_threads(room_id: int, sort: str = "recent",
                             u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    q = db.query(ForumThread).filter(ForumThread.room_id == room_id)
    if sort == "top":
        q = q.order_by(ForumThread.is_pinned.desc(), ForumThread.upvotes.desc())
    else:
        q = q.order_by(ForumThread.is_pinned.desc(), ForumThread.last_reply_at.desc().nullslast())
    threads = q.limit(50).all()
    return {"threads": [
        {"id": t.id, "title": t.title, "creator_id": t.creator_id,
         "tags": json.loads(t.tags or "[]"), "is_pinned": t.is_pinned,
         "is_locked": t.is_locked, "is_solved": t.is_solved,
         "reply_count": t.reply_count, "upvotes": t.upvotes,
         "created_at": t.created_at.isoformat() if t.created_at else ""}
        for t in threads
    ]}

@router.post("/{room_id}/forum", status_code=201)
async def create_forum_thread(room_id: int, body: ForumThreadCreate,
                              u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    t = ForumThread(
        room_id=room_id, title=body.title, body=body.body,
        creator_id=u.id, tags=json.dumps(body.tags),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"id": t.id, "title": t.title}

@router.get("/{room_id}/forum/{thread_id}")
async def get_forum_thread(room_id: int, thread_id: int,
                           u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    t = db.query(ForumThread).filter(ForumThread.id == thread_id, ForumThread.room_id == room_id).first()
    if not t:
        raise HTTPException(404, "Thread not found")
    return {
        "id": t.id, "title": t.title, "body": t.body, "creator_id": t.creator_id,
        "tags": json.loads(t.tags or "[]"), "is_pinned": t.is_pinned,
        "is_locked": t.is_locked, "is_solved": t.is_solved,
        "reply_count": t.reply_count, "upvotes": t.upvotes,
        "created_at": t.created_at.isoformat() if t.created_at else "",
    }

@router.put("/{room_id}/forum/{thread_id}")
async def update_forum_thread(room_id: int, thread_id: int, body: ForumThreadUpdate,
                              u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    t = db.query(ForumThread).filter(ForumThread.id == thread_id, ForumThread.room_id == room_id).first()
    if not t:
        raise HTTPException(404, "Thread not found")
    if body.title is not None: t.title = body.title
    if body.is_pinned is not None: t.is_pinned = body.is_pinned
    if body.is_locked is not None: t.is_locked = body.is_locked
    if body.is_solved is not None: t.is_solved = body.is_solved
    if body.tags is not None: t.tags = json.dumps(body.tags)
    db.commit()
    return {"ok": True}

@router.post("/{room_id}/forum/{thread_id}/upvote")
async def upvote_thread(room_id: int, thread_id: int,
                        u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    t = db.query(ForumThread).filter(ForumThread.id == thread_id, ForumThread.room_id == room_id).first()
    if not t:
        raise HTTPException(404, "Thread not found")
    t.upvotes = (t.upvotes or 0) + 1
    db.commit()
    return {"ok": True, "upvotes": t.upvotes}


# ══════════════════════════════════════════════════════════════════════════════
# Granular Permissions
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/permissions")
async def get_permissions(room_id: int,
                          u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    perms = db.query(Permission).filter(Permission.room_id == room_id).all()
    return {
        "permissions": [
            {"id": p.id, "role": p.role.value if p.role else None,
             "user_id": p.user_id, "allow": p.allow, "deny": p.deny}
            for p in perms
        ],
        "available_flags": PermissionFlags.all_flags(),
    }

@router.put("/{room_id}/permissions")
async def set_permission(room_id: int, body: PermissionUpdate,
                         u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    if body.role:
        existing = db.query(Permission).filter(
            Permission.room_id == room_id, Permission.role == body.role,
        ).first()
    elif body.user_id:
        existing = db.query(Permission).filter(
            Permission.room_id == room_id, Permission.user_id == body.user_id,
        ).first()
    else:
        raise HTTPException(400, "Specify role or user_id")

    if existing:
        existing.allow = body.allow
        existing.deny = body.deny
    else:
        p = Permission(
            room_id=room_id,
            role=RoomRole(body.role) if body.role else None,
            user_id=body.user_id,
            allow=body.allow, deny=body.deny,
        )
        db.add(p)
    db.commit()
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Auto-Moderation Rules
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/automod")
async def list_automod_rules(room_id: int,
                             u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    rules = db.query(AutoModRule).filter(AutoModRule.room_id == room_id).all()
    return {"rules": [
        {"id": r.id, "name": r.name, "rule_type": r.rule_type,
         "pattern": r.pattern, "action": r.action, "is_enabled": r.is_enabled,
         "mute_duration_seconds": r.mute_duration_seconds,
         "trigger_count": r.trigger_count}
        for r in rules
    ]}

@router.post("/{room_id}/automod", status_code=201)
async def create_automod_rule(room_id: int, body: AutoModRuleCreate,
                              u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    # Validate regex if rule_type is regex
    if body.rule_type == "regex":
        try:
            re.compile(body.pattern)
        except re.error as e:
            raise HTTPException(400, f"Invalid regex: {e}")
    rule = AutoModRule(
        room_id=room_id, name=body.name, rule_type=body.rule_type,
        pattern=body.pattern, action=body.action,
        mute_duration_seconds=body.mute_duration_seconds, creator_id=u.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "name": rule.name}

@router.put("/{room_id}/automod/{rule_id}")
async def update_automod_rule(room_id: int, rule_id: int, body: AutoModRuleUpdate,
                              u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    rule = db.query(AutoModRule).filter(AutoModRule.id == rule_id, AutoModRule.room_id == room_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    if body.name is not None: rule.name = body.name
    if body.is_enabled is not None: rule.is_enabled = body.is_enabled
    if body.pattern is not None: rule.pattern = body.pattern
    if body.action is not None: rule.action = body.action
    db.commit()
    return {"ok": True}

@router.delete("/{room_id}/automod/{rule_id}")
async def delete_automod_rule(room_id: int, rule_id: int,
                              u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    rule = db.query(AutoModRule).filter(AutoModRule.id == rule_id, AutoModRule.room_id == room_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    db.delete(rule)
    db.commit()
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Per-User Slowmode
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/slowmode/users")
async def list_user_slowmodes(room_id: int,
                              u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    entries = db.query(UserSlowmode).filter(UserSlowmode.room_id == room_id).all()
    return {"slowmodes": [
        {"user_id": e.user_id, "cooldown_seconds": e.cooldown_seconds}
        for e in entries
    ]}

@router.put("/{room_id}/slowmode/users")
async def set_user_slowmode(room_id: int, body: UserSlowmodeSet,
                            u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(room_id, u.id, db)
    existing = db.query(UserSlowmode).filter(
        UserSlowmode.room_id == room_id, UserSlowmode.user_id == body.user_id,
    ).first()
    if body.cooldown_seconds == 0:
        if existing:
            db.delete(existing)
            db.commit()
        return {"ok": True, "removed": True}
    if existing:
        existing.cooldown_seconds = body.cooldown_seconds
    else:
        db.add(UserSlowmode(
            room_id=room_id, user_id=body.user_id,
            cooldown_seconds=body.cooldown_seconds, set_by=u.id,
        ))
    db.commit()
    return {"ok": True, "cooldown_seconds": body.cooldown_seconds}


# ══════════════════════════════════════════════════════════════════════════════
# Auto-Mod Check (called from chat.py before broadcasting)
# ══════════════════════════════════════════════════════════════════════════════

async def check_automod(room_id: int, user_id: int, text: str, member_role: RoomRole,
                        db: Session) -> dict | None:
    """
    Check message against auto-moderation rules.

    Returns None if message passes, or {"action": ..., "rule": ...} if blocked.
    """
    rules = db.query(AutoModRule).filter(
        AutoModRule.room_id == room_id, AutoModRule.is_enabled == True,
    ).all()

    for rule in rules:
        exempt = json.loads(rule.exempt_roles or "[]")
        if member_role.value in exempt:
            continue

        matched = False
        if rule.rule_type == "regex":
            try:
                if re.search(rule.pattern, text, re.IGNORECASE):
                    matched = True
            except re.error:
                continue
        elif rule.rule_type == "word_filter":
            words = [w.strip().lower() for w in rule.pattern.split(",") if w.strip()]
            text_lower = text.lower()
            if any(w in text_lower for w in words):
                matched = True
        elif rule.rule_type == "link_whitelist":
            import re as _re
            urls = _re.findall(r"https?://\S+", text, _re.IGNORECASE)
            allowed = [d.strip().lower() for d in rule.pattern.split(",") if d.strip()]
            for url in urls:
                domain = url.split("//")[-1].split("/")[0].lower()
                if not any(domain.endswith(a) for a in allowed):
                    matched = True
                    break
        elif rule.rule_type == "caps_filter":
            alpha = [c for c in text if c.isalpha()]
            if len(alpha) >= 20:
                ratio = sum(1 for c in alpha if c.isupper()) / len(alpha)
                threshold = float(rule.pattern) if rule.pattern.replace(".", "").isdigit() else 0.8
                if ratio >= threshold:
                    matched = True

        if matched:
            rule.trigger_count = (rule.trigger_count or 0) + 1
            db.commit()
            return {"action": rule.action, "rule_name": rule.name, "rule_id": rule.id,
                    "mute_duration": rule.mute_duration_seconds}

    return None
