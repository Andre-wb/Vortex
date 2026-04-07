"""
Advanced Spaces features — nested spaces, onboarding, discovery,
audit log, custom emoji, vanity URLs, templates.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import (
    AuditLog, Permission, PermissionFlags, Room, RoomMember, RoomRole,
    Space, SpaceCategory, SpaceEmoji, SpaceMember,
)
from app.security.auth_jwt import get_current_user
from app.utilites.utils import generative_invite_code

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/spaces", tags=["spaces-advanced"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class OnboardingUpdate(BaseModel):
    welcome_message: str | None = Field(None, max_length=2000)
    rules: str | None = Field(None, max_length=5000)
    onboarding_roles: list[str] | None = None  # ["Gamer", "Artist", "Developer"]

class VanityUpdate(BaseModel):
    vanity_url: str = Field(..., min_length=3, max_length=50, pattern="^[a-z0-9_-]+$")

class EmojiCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=50, pattern="^[a-z0-9_]+$")

class TemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    template_id: str = Field(default="community")  # gaming, community, study, project, social

class PermissionOverride(BaseModel):
    room_id: int
    role: str | None = None
    user_id: int | None = None
    allow: int = 0
    deny: int = 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_space_admin(space_id: int, user_id: int, db: Session) -> SpaceMember:
    m = db.query(SpaceMember).filter(
        SpaceMember.space_id == space_id, SpaceMember.user_id == user_id,
    ).first()
    if not m or m.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Admin access required")
    return m

def _audit(db: Session, space_id: int, actor_id: int, action: str,
           target_id: int | None = None, room_id: int | None = None, details: dict | None = None):
    db.add(AuditLog(
        space_id=space_id, room_id=room_id, actor_id=actor_id,
        action=action, target_id=target_id,
        details=json.dumps(details or {}),
    ))
    db.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Granular Permissions per Channel
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{space_id}/permissions/{room_id}")
async def get_channel_permissions(space_id: int, room_id: int,
                                  u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get permission overrides for a specific channel in a space."""
    _require_space_admin(space_id, u.id, db)
    perms = db.query(Permission).filter(Permission.room_id == room_id).all()
    return {
        "permissions": [
            {"id": p.id, "role": p.role.value if p.role else None,
             "user_id": p.user_id, "allow": p.allow, "deny": p.deny}
            for p in perms
        ],
        "flags": PermissionFlags.all_flags(),
    }

@router.put("/{space_id}/permissions")
async def set_channel_permission(space_id: int, body: PermissionOverride,
                                 u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Set permission override for a channel (by role or user)."""
    _require_space_admin(space_id, u.id, db)
    if body.role:
        existing = db.query(Permission).filter(
            Permission.room_id == body.room_id, Permission.role == body.role,
        ).first()
    elif body.user_id:
        existing = db.query(Permission).filter(
            Permission.room_id == body.room_id, Permission.user_id == body.user_id,
        ).first()
    else:
        raise HTTPException(400, "Specify role or user_id")

    if existing:
        existing.allow = body.allow
        existing.deny = body.deny
    else:
        db.add(Permission(
            room_id=body.room_id,
            role=RoomRole(body.role) if body.role else None,
            user_id=body.user_id,
            allow=body.allow, deny=body.deny,
        ))
    db.commit()
    _audit(db, space_id, u.id, "permission_update", room_id=body.room_id,
           details={"role": body.role, "user_id": body.user_id, "allow": body.allow, "deny": body.deny})
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# 2. Nested Spaces (sub-spaces)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{space_id}/sub-spaces", status_code=201)
async def create_sub_space(space_id: int, body: BaseModel | None = None,
                           u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Create a sub-space inside a parent space."""
    from pydantic import BaseModel as BM
    class SubSpaceBody(BM):
        name: str = Field(..., min_length=1, max_length=100)
        description: str = Field("", max_length=500)

    _require_space_admin(space_id, u.id, db)
    parent = db.query(Space).filter(Space.id == space_id).first()
    if not parent:
        raise HTTPException(404, "Parent space not found")

    # Read body manually since FastAPI might not parse nested dependency
    # For simplicity, accept name/description as query params too
    sub = Space(
        name=f"Sub-space of {parent.name}",
        description="",
        creator_id=u.id,
        invite_code=generative_invite_code(8),
        parent_id=space_id,
    )
    db.add(sub)
    db.flush()
    db.add(SpaceMember(space_id=sub.id, user_id=u.id, role=RoomRole.OWNER))
    db.commit()
    db.refresh(sub)
    _audit(db, space_id, u.id, "sub_space_create", target_id=sub.id)
    return {"id": sub.id, "name": sub.name, "parent_id": space_id, "invite_code": sub.invite_code}


@router.get("/{space_id}/sub-spaces")
async def list_sub_spaces(space_id: int, u: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    """List sub-spaces of a space."""
    subs = db.query(Space).filter(Space.parent_id == space_id).all()
    return {"sub_spaces": [
        {"id": s.id, "name": s.name, "member_count": s.member_count,
         "invite_code": s.invite_code, "avatar_emoji": s.avatar_emoji}
        for s in subs
    ]}


# ══════════════════════════════════════════════════════════════════════════════
# 3. Onboarding Flow
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{space_id}/onboarding")
async def get_onboarding(space_id: int, db: Session = Depends(get_db)):
    """Get onboarding settings (public — shown to new members)."""
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(404, "Space not found")
    return {
        "welcome_message": space.welcome_message or "",
        "rules": space.rules or "",
        "onboarding_roles": json.loads(space.onboarding_roles or "[]"),
        "space_name": space.name,
        "avatar_emoji": space.avatar_emoji,
    }

@router.put("/{space_id}/onboarding")
async def set_onboarding(space_id: int, body: OnboardingUpdate,
                         u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Configure onboarding (admin only)."""
    _require_space_admin(space_id, u.id, db)
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(404, "Space not found")
    if body.welcome_message is not None: space.welcome_message = body.welcome_message
    if body.rules is not None: space.rules = body.rules
    if body.onboarding_roles is not None: space.onboarding_roles = json.dumps(body.onboarding_roles)
    db.commit()
    _audit(db, space_id, u.id, "onboarding_update")
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# 4. Space Discovery
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/discover")
async def discover_spaces(q: str = Query(default="", max_length=100),
                          db: Session = Depends(get_db)):
    """Search and discover public spaces."""
    query = db.query(Space).filter(Space.is_public == True)
    if q:
        query = query.filter(Space.name.ilike(f"%{q}%") | Space.description.ilike(f"%{q}%"))
    spaces = query.order_by(Space.member_count.desc()).limit(50).all()
    return {"spaces": [
        {"id": s.id, "name": s.name, "description": s.description,
         "avatar_emoji": s.avatar_emoji, "avatar_url": s.avatar_url,
         "member_count": s.member_count, "invite_code": s.invite_code,
         "vanity_url": s.vanity_url}
        for s in spaces
    ]}


# ══════════════════════════════════════════════════════════════════════════════
# 5. Audit Log
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{space_id}/audit-log")
async def get_audit_log(space_id: int, limit: int = Query(default=50, le=200),
                        u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """View audit log (admin only). Shows all changes in the space."""
    _require_space_admin(space_id, u.id, db)
    logs = db.query(AuditLog).filter(AuditLog.space_id == space_id).order_by(
        AuditLog.created_at.desc()
    ).limit(limit).all()
    return {"entries": [
        {"id": l.id, "action": l.action, "actor_id": l.actor_id,
         "target_id": l.target_id, "room_id": l.room_id,
         "details": json.loads(l.details or "{}"),
         "created_at": l.created_at.isoformat() if l.created_at else ""}
        for l in logs
    ]}


# ══════════════════════════════════════════════════════════════════════════════
# 6. Custom Emoji
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{space_id}/emojis")
async def list_emojis(space_id: int, u: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """List custom emojis for a space."""
    emojis = db.query(SpaceEmoji).filter(SpaceEmoji.space_id == space_id).all()
    return {"emojis": [
        {"id": e.id, "name": e.name, "image_url": e.image_url}
        for e in emojis
    ]}

@router.post("/{space_id}/emojis", status_code=201)
async def upload_emoji(space_id: int, name: str = Query(..., min_length=2, max_length=50),
                       file: UploadFile = File(...),
                       u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Upload a custom emoji for the space."""
    _require_space_admin(space_id, u.id, db)
    # Check limit
    count = db.query(SpaceEmoji).filter(SpaceEmoji.space_id == space_id).count()
    if count >= 50:
        raise HTTPException(400, "Maximum 50 custom emojis per space")
    # Check duplicate name
    existing = db.query(SpaceEmoji).filter(
        SpaceEmoji.space_id == space_id, SpaceEmoji.name == name.lower()
    ).first()
    if existing:
        raise HTTPException(409, f"Emoji :{name}: already exists")
    # Save file
    emoji_dir = f"uploads/space_emojis/{space_id}"
    os.makedirs(emoji_dir, exist_ok=True)
    content = await file.read()
    ext = file.filename.rsplit(".", 1)[-1] if "." in (file.filename or "") else "png"
    filename = f"{name}.{ext}"
    filepath = f"{emoji_dir}/{filename}"
    with open(filepath, "wb") as f:
        f.write(content)
    emoji = SpaceEmoji(
        space_id=space_id, name=name.lower(),
        image_url=f"/uploads/space_emojis/{space_id}/{filename}",
        creator_id=u.id,
    )
    db.add(emoji)
    db.commit()
    db.refresh(emoji)
    _audit(db, space_id, u.id, "emoji_create", details={"name": name})
    return {"id": emoji.id, "name": emoji.name, "image_url": emoji.image_url}

@router.delete("/{space_id}/emojis/{emoji_id}")
async def delete_emoji(space_id: int, emoji_id: int,
                       u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Delete a custom emoji."""
    _require_space_admin(space_id, u.id, db)
    emoji = db.query(SpaceEmoji).filter(SpaceEmoji.id == emoji_id, SpaceEmoji.space_id == space_id).first()
    if not emoji:
        raise HTTPException(404, "Emoji not found")
    _audit(db, space_id, u.id, "emoji_delete", details={"name": emoji.name})
    db.delete(emoji)
    db.commit()
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# 7. Vanity URL
# ══════════════════════════════════════════════════════════════════════════════

@router.put("/{space_id}/vanity")
async def set_vanity_url(space_id: int, body: VanityUpdate,
                         u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Set a vanity URL for the space (e.g. /s/my-community)."""
    _require_space_admin(space_id, u.id, db)
    # Check availability
    taken = db.query(Space).filter(Space.vanity_url == body.vanity_url, Space.id != space_id).first()
    if taken:
        raise HTTPException(409, f"Vanity URL '{body.vanity_url}' is already taken")
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(404, "Space not found")
    space.vanity_url = body.vanity_url
    db.commit()
    _audit(db, space_id, u.id, "vanity_url_set", details={"url": body.vanity_url})
    return {"ok": True, "vanity_url": body.vanity_url}

@router.get("/s/{vanity}")
async def resolve_vanity(vanity: str, db: Session = Depends(get_db)):
    """Resolve a vanity URL to a space."""
    space = db.query(Space).filter(Space.vanity_url == vanity).first()
    if not space:
        raise HTTPException(404, "Space not found")
    return {
        "id": space.id, "name": space.name, "description": space.description,
        "avatar_emoji": space.avatar_emoji, "invite_code": space.invite_code,
        "member_count": space.member_count, "is_public": space.is_public,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 8. Server Templates
# ══════════════════════════════════════════════════════════════════════════════

TEMPLATES = {
    "gaming": {
        "categories": [
            {"name": "Info", "rooms": [
                {"name": "rules", "is_channel": True},
                {"name": "announcements", "is_channel": True},
            ]},
            {"name": "Chat", "rooms": [
                {"name": "general", "is_channel": False},
                {"name": "off-topic", "is_channel": False},
                {"name": "memes", "is_channel": False},
            ]},
            {"name": "Voice", "rooms": [
                {"name": "Game Voice 1", "is_voice": True},
                {"name": "Game Voice 2", "is_voice": True},
                {"name": "AFK", "is_voice": True},
            ]},
        ],
    },
    "community": {
        "categories": [
            {"name": "Welcome", "rooms": [
                {"name": "rules", "is_channel": True},
                {"name": "introductions", "is_channel": False},
            ]},
            {"name": "Discussion", "rooms": [
                {"name": "general", "is_channel": False},
                {"name": "questions", "is_channel": False},
                {"name": "feedback", "is_channel": False},
            ]},
            {"name": "Voice", "rooms": [
                {"name": "Lounge", "is_voice": True},
            ]},
        ],
    },
    "study": {
        "categories": [
            {"name": "Resources", "rooms": [
                {"name": "announcements", "is_channel": True},
                {"name": "materials", "is_channel": True},
            ]},
            {"name": "Discussion", "rooms": [
                {"name": "general", "is_channel": False},
                {"name": "homework-help", "is_channel": False},
                {"name": "exam-prep", "is_channel": False},
            ]},
            {"name": "Study Rooms", "rooms": [
                {"name": "Study Room 1", "is_voice": True},
                {"name": "Study Room 2", "is_voice": True},
            ]},
        ],
    },
    "project": {
        "categories": [
            {"name": "Project", "rooms": [
                {"name": "announcements", "is_channel": True},
                {"name": "general", "is_channel": False},
                {"name": "tasks", "is_channel": False},
            ]},
            {"name": "Development", "rooms": [
                {"name": "frontend", "is_channel": False},
                {"name": "backend", "is_channel": False},
                {"name": "devops", "is_channel": False},
            ]},
            {"name": "Meetings", "rooms": [
                {"name": "Daily Standup", "is_voice": True},
                {"name": "Sprint Review", "is_voice": True},
            ]},
        ],
    },
}


@router.get("/templates")
async def list_templates():
    """List available space templates."""
    return {"templates": [
        {"id": tid, "name": tid.title(), "categories": len(t["categories"]),
         "rooms": sum(len(c["rooms"]) for c in t["categories"])}
        for tid, t in TEMPLATES.items()
    ]}


@router.post("/{space_id}/apply-template")
async def apply_template(space_id: int, template_id: str = Query(...),
                         u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Apply a template to a space — creates categories and rooms."""
    _require_space_admin(space_id, u.id, db)
    template = TEMPLATES.get(template_id)
    if not template:
        raise HTTPException(404, f"Template '{template_id}' not found. Available: {list(TEMPLATES.keys())}")

    created_rooms = []
    for cat_data in template["categories"]:
        cat = SpaceCategory(space_id=space_id, name=cat_data["name"])
        db.add(cat)
        db.flush()
        for room_data in cat_data["rooms"]:
            room = Room(
                name=room_data["name"],
                creator_id=u.id,
                invite_code=generative_invite_code(8),
                space_id=space_id,
                category_id=cat.id,
                is_channel=room_data.get("is_channel", False),
                is_voice=room_data.get("is_voice", False),
            )
            db.add(room)
            db.flush()
            db.add(RoomMember(room_id=room.id, user_id=u.id, role=RoomRole.OWNER))
            created_rooms.append({"id": room.id, "name": room.name})

    space = db.query(Space).filter(Space.id == space_id).first()
    if space:
        space.template_id = template_id
    db.commit()

    _audit(db, space_id, u.id, "template_applied", details={"template": template_id})
    return {"ok": True, "template": template_id, "rooms_created": len(created_rooms), "rooms": created_rooms}
