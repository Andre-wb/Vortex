"""app/chats/stories.py — Stories API (24h ephemeral)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Story
from app.security.auth_jwt import get_current_user

router = APIRouter(prefix="/api/stories", tags=["stories"])

UPLOAD_DIR = Path("static/uploads/stories")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_SIZE = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".webm", ".mov", ".mp3", ".ogg", ".m4a"}


def _dt(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z" if dt else None


def _story_dict(s: Story, u: User) -> dict:
    return {
        "id": s.id,
        "user_id": s.user_id,
        "username": u.username,
        "display_name": u.display_name or u.username,
        "avatar_emoji": u.avatar_emoji,
        "avatar_url": u.avatar_url,
        "media_type": s.media_type,
        "media_url": s.media_url,
        "music_url": s.music_url,
        "text": s.text,
        "text_color": s.text_color,
        "bg_color": s.bg_color,
        "music_title": s.music_title,
        "duration": s.duration or 5,
        "views_count": s.views_count or 0,
        "created_at": _dt(s.created_at),
        "expires_at": _dt(s.expires_at),
    }


@router.get("")
async def get_stories(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Active stories grouped by user: self first, then contacts."""
    from app.models.contact import Contact

    # Use both aware and naive timestamps for DB compatibility (PostgreSQL vs SQLite)
    now_aware = datetime.now(timezone.utc)
    now_naive = now_aware.replace(tzinfo=None)

    contact_ids = [
        c.contact_id
        for c in db.query(Contact).filter(Contact.owner_id == u.id).all()
    ]
    user_ids = list({u.id} | set(contact_ids))

    # Try aware first (PostgreSQL), fallback to naive (SQLite)
    try:
        stories = (
            db.query(Story)
            .filter(Story.user_id.in_(user_ids), Story.expires_at > now_aware)
            .order_by(Story.user_id, Story.created_at)
            .all()
        )
    except Exception:
        stories = (
            db.query(Story)
            .filter(Story.user_id.in_(user_ids), Story.expires_at > now_naive)
            .order_by(Story.user_id, Story.created_at)
            .all()
        )

    groups: dict[int, dict] = {}
    for s in stories:
        if s.user_id not in groups:
            su = db.query(User).filter(User.id == s.user_id).first()
            if not su:
                continue
            groups[s.user_id] = {
                "user_id": s.user_id,
                "username": su.username,
                "display_name": su.display_name or su.username,
                "avatar_emoji": su.avatar_emoji,
                "avatar_url": su.avatar_url,
                "is_self": s.user_id == u.id,
                "stories": [],
            }
        groups[s.user_id]["stories"].append(_story_dict(s, su))

    # patch user objects into dicts properly
    result = list(groups.values())
    result.sort(key=lambda x: (not x["is_self"],))
    return {"story_groups": result}


@router.post("", status_code=201)
async def create_story(
    media_type: str = Form(...),
    text: Optional[str] = Form(None),
    text_color: str = Form("#ffffff"),
    bg_color: str = Form("linear-gradient(135deg,#667eea 0%,#764ba2 100%)"),
    music_title: Optional[str] = Form(None),
    duration: int = Form(5),
    file: Optional[UploadFile] = File(None),
    music_file: Optional[UploadFile] = File(None),
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if media_type not in ("photo", "video", "text"):
        raise HTTPException(400, "Invalid media_type")

    async def _save(f: UploadFile) -> str:
        ext = Path(f.filename or "").suffix.lower() or ".bin"
        if ext not in ALLOWED_EXT:
            raise HTTPException(400, f"File type {ext} not allowed")
        data = await f.read()
        if len(data) > MAX_SIZE:
            raise HTTPException(413, "File too large (max 50 MB)")
        name = f"{uuid.uuid4()}{ext}"
        (UPLOAD_DIR / name).write_bytes(data)
        return f"/static/uploads/stories/{name}"

    media_url = await _save(file) if file else None
    music_url = await _save(music_file) if music_file else None

    story = Story(
        user_id=u.id,
        media_type=media_type,
        media_url=media_url,
        music_url=music_url,
        text=text[:500] if text else None,
        text_color=text_color,
        bg_color=bg_color,
        music_title=music_title[:80] if music_title else None,
        duration=max(1, min(60, duration)),
    )
    db.add(story)
    db.commit()
    db.refresh(story)
    return _story_dict(story, u)


@router.delete("/{story_id}")
async def delete_story(
    story_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    story = db.query(Story).filter(Story.id == story_id, Story.user_id == u.id).first()
    if not story:
        raise HTTPException(404, "Story not found")
    for url in (story.media_url, story.music_url):
        if url:
            try:
                # Безопасное удаление: только из UPLOAD_DIR
                fname = Path(url).name
                safe_path = (UPLOAD_DIR / fname).resolve()
                if safe_path.parent == UPLOAD_DIR.resolve() and safe_path.exists():
                    safe_path.unlink()
            except Exception:
                pass
    db.delete(story)
    db.commit()
    return {"ok": True}


@router.post("/{story_id}/view")
async def view_story(
    story_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from sqlalchemy import update as sa_update
    db.execute(
        sa_update(Story)
        .where(Story.id == story_id, Story.user_id != u.id)
        .values(views_count=Story.views_count + 1)
    )
    db.commit()
    return {"ok": True}


@router.post("/{story_id}/react")
async def react_to_story(
    story_id: int,
    emoji: str = Form("❤️"),
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """React to a story with an emoji. Notifies the story owner."""
    story = db.query(Story).filter(Story.id == story_id).first()
    if not story:
        raise HTTPException(404, "Story not found")
    if story.user_id == u.id:
        raise HTTPException(400, "Cannot react to own story")

    from app.peer.connection_manager import manager
    await manager.notify_user(story.user_id, {
        "type": "story_reaction",
        "story_id": story_id,
        "emoji": emoji[:10],
        "from_user_id": u.id,
        "from_username": u.username,
        "from_display_name": u.display_name or u.username,
        "from_avatar": u.avatar_emoji,
    })
    return {"ok": True}


@router.post("/{story_id}/reply")
async def reply_to_story(
    story_id: int,
    text: str = Form(...),
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Reply to a story with text. Notifies the story owner."""
    story = db.query(Story).filter(Story.id == story_id).first()
    if not story:
        raise HTTPException(404, "Story not found")
    if story.user_id == u.id:
        raise HTTPException(400, "Cannot reply to own story")

    from app.peer.connection_manager import manager
    await manager.notify_user(story.user_id, {
        "type": "story_reply",
        "story_id": story_id,
        "text": text[:1000],
        "from_user_id": u.id,
        "from_username": u.username,
        "from_display_name": u.display_name or u.username,
        "from_avatar": u.avatar_emoji,
    })
    return {"ok": True}
