"""
app/chats/channel_feeds.py — RSS feeds and webhook auto-posting for channels.

Endpoints:
  POST   /api/channels/{room_id}/feeds         — add RSS or webhook feed (owner/admin)
  GET    /api/channels/{room_id}/feeds         — list feeds (owner/admin)
  DELETE /api/channels/{room_id}/feeds/{fid}   — remove feed (owner/admin)
  POST   /api/channels/{room_id}/webhook       — receive incoming webhook (public, no auth)

Background:
  poll_rss_feeds(db) — fetch all active RSS feeds, post new items as channel messages.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import ChannelFeed, Message, MessageType, Room, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/channels", tags=["channel-feeds"])

# ── Pydantic ──────────────────────────────────────────────────────────────────

class AddFeedRequest(BaseModel):
    type: str = Field(..., pattern="^(rss|webhook)$")
    url: str = Field(default="", max_length=2048)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_admin(room_id: int, user: User, db: Session) -> None:
    channel = db.query(Room).filter(Room.id == room_id, Room.is_channel == True).first()
    if not channel:
        raise HTTPException(404, "Channel not found")
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id, RoomMember.user_id == user.id
    ).first()
    if not member or member.role not in (RoomRole.OWNER, RoomRole.ADMIN):
        raise HTTPException(403, "Owner/admin only")


def _feed_dict(f: ChannelFeed) -> dict:
    return {
        "id": f.id,
        "room_id": f.room_id,
        "feed_type": f.feed_type,
        "url": f.url,
        "last_fetched": f.last_fetched.isoformat() if f.last_fetched else None,
        "is_active": f.is_active,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _is_ssrf_safe(url: str) -> bool:
    """Check if URL is safe from SSRF (not pointing to internal services)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname or ""
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return False
        # Resolve DNS and check IP
        try:
            ip = socket.getaddrinfo(hostname, None)[0][4][0]
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except (socket.gaierror, ValueError):
            pass
        return True
    except Exception:
        return False


async def _post_channel_message(room_id: int, text: str, db: Session) -> None:
    """Post a plain-text message to a channel on behalf of the system (sender_id=None)."""
    # Store as UTF-8 bytes — for channels, content may be unencrypted plain text
    payload = text.encode("utf-8")
    msg = Message(
        room_id=room_id,
        sender_id=None,
        msg_type=MessageType.TEXT,
        content_encrypted=payload,
    )
    db.add(msg)
    db.flush()
    db.refresh(msg)
    db.commit()

    # Broadcast over WebSocket
    try:
        await manager.broadcast_to_room(room_id, {
            "type": "message",
            "msg_id": msg.id,
            "room_id": room_id,
            "sender_id": None,
            "msg_type": MessageType.TEXT.value,
            "ciphertext": payload.hex(),
            "created_at": msg.created_at.isoformat() if msg.created_at else "",
        })
    except Exception as e:
        logger.warning("WS broadcast failed for channel %s feed message: %s", room_id, e)


# ══════════════════════════════════════════════════════════════════════════════
# REST endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{room_id}/feeds", status_code=201)
async def add_feed(room_id: int, body: AddFeedRequest,
                   u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Add an RSS feed or create a webhook endpoint for a channel."""
    _require_admin(room_id, u, db)

    if body.type == "webhook":
        # Generate a unique secret key used as the webhook path token
        secret = secrets.token_urlsafe(32)
        feed = ChannelFeed(room_id=room_id, feed_type="webhook", url=secret, is_active=True)
    else:
        if not body.url:
            raise HTTPException(400, "url is required for rss feeds")
        if not _is_ssrf_safe(body.url):
            raise HTTPException(400, "URL points to an internal/private address")
        # Check for duplicate
        existing = db.query(ChannelFeed).filter(
            ChannelFeed.room_id == room_id,
            ChannelFeed.feed_type == "rss",
            ChannelFeed.url == body.url,
        ).first()
        if existing:
            raise HTTPException(409, "This RSS feed is already added")
        feed = ChannelFeed(room_id=room_id, feed_type="rss", url=body.url, is_active=True)

    db.add(feed)
    db.commit()
    db.refresh(feed)
    return _feed_dict(feed)


@router.get("/{room_id}/feeds")
async def list_feeds(room_id: int, u: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """List all feeds for a channel (owner/admin only)."""
    _require_admin(room_id, u, db)
    feeds = db.query(ChannelFeed).filter(ChannelFeed.room_id == room_id).all()
    return {"feeds": [_feed_dict(f) for f in feeds]}


@router.delete("/{room_id}/feeds/{feed_id}", status_code=204)
async def delete_feed(room_id: int, feed_id: int, u: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """Remove a feed."""
    _require_admin(room_id, u, db)
    feed = db.query(ChannelFeed).filter(
        ChannelFeed.id == feed_id, ChannelFeed.room_id == room_id
    ).first()
    if not feed:
        raise HTTPException(404, "Feed not found")
    db.delete(feed)
    db.commit()


@router.post("/{room_id}/webhook")
async def receive_webhook(room_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Public endpoint — receive an incoming webhook POST and post it as a channel message.

    The caller must pass ?secret=<key> matching the stored webhook token.
    Body: any JSON. If it contains a "text" or "message" field, that is posted.
    Otherwise the whole body is serialised as a message.
    """
    secret = request.query_params.get("secret", "")
    if not secret:
        raise HTTPException(400, "Missing secret query parameter")

    feed = db.query(ChannelFeed).filter(
        ChannelFeed.room_id == room_id,
        ChannelFeed.feed_type == "webhook",
        ChannelFeed.url == secret,
        ChannelFeed.is_active == True,
    ).first()
    if not feed:
        raise HTTPException(403, "Invalid webhook secret")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Request body must be valid JSON")

    text = body.get("text") or body.get("message") or body.get("content") or ""
    if not text:
        import json
        text = json.dumps(body, ensure_ascii=False)

    # Truncate to a sane limit
    text = text[:4096]

    await _post_channel_message(room_id, text, db)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# RSS polling background task
# ══════════════════════════════════════════════════════════════════════════════

_XML_NAMESPACES = {
    "atom": "http://www.w3.org/2005/Atom",
    "content": "http://purl.org/rss/1.0/modules/content/",
    "media": "http://search.yahoo.com/mrss/",
}


def _parse_rss(xml_bytes: bytes) -> list[dict]:
    """
    Parse RSS 2.0 or Atom feed. Returns list of items newest-first:
      {"guid": str, "title": str, "link": str, "summary": str}
    """
    items: list[dict] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        logger.warning("RSS XML parse error: %s", e)
        return items

    tag = root.tag.lower()

    # ── Atom feed ──────────────────────────────────────────────────────────
    if "atom" in tag or root.tag == "{http://www.w3.org/2005/Atom}feed":
        ns = "http://www.w3.org/2005/Atom"
        for entry in root.findall(f"{{{ns}}}entry"):
            guid = (entry.findtext(f"{{{ns}}}id") or "").strip()
            title = (entry.findtext(f"{{{ns}}}title") or "").strip()
            link_el = entry.find(f"{{{ns}}}link")
            link = (link_el.get("href", "") if link_el is not None else "").strip()
            summary = (entry.findtext(f"{{{ns}}}summary") or
                       entry.findtext(f"{{{ns}}}content") or "").strip()
            items.append({"guid": guid or link, "title": title, "link": link, "summary": summary})
        return items

    # ── RSS 2.0 ────────────────────────────────────────────────────────────
    channel_el = root.find("channel")
    entries = (channel_el.findall("item") if channel_el is not None else root.findall(".//item"))
    for item in entries:
        guid = (item.findtext("guid") or item.findtext("link") or "").strip()
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        summary = (item.findtext("description") or "").strip()
        # Strip basic HTML from summary (< ... >)
        import re
        summary = re.sub(r"<[^>]+>", "", summary).strip()
        items.append({"guid": guid, "title": title, "link": link, "summary": summary})

    return items


async def poll_rss_feeds(db: Session) -> None:
    """
    Fetch all active RSS feeds and post new items as channel messages.
    Should be called periodically (e.g. every 5 minutes) from the background loop.
    """
    feeds = db.query(ChannelFeed).filter(
        ChannelFeed.feed_type == "rss",
        ChannelFeed.is_active == True,
    ).all()

    if not feeds:
        return

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        for feed in feeds:
            # SSRF check — skip feeds pointing to internal addresses
            if not _is_ssrf_safe(feed.url):
                logger.warning("RSS feed %s (%s) skipped — URL points to private/internal address", feed.id, feed.url)
                continue
            try:
                resp = await client.get(feed.url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                resp.raise_for_status()
            except Exception as e:
                logger.warning("RSS fetch failed for feed %s (%s): %s", feed.id, feed.url, e)
                continue

            items = _parse_rss(resp.content)
            if not items:
                continue

            # Items are newest-first; we want to post oldest-new first
            # Find items after last_item_id
            new_items: list[dict] = []
            for item in reversed(items):  # oldest-first now
                if feed.last_item_id and item["guid"] == feed.last_item_id:
                    # Everything after this is already posted
                    new_items = []
                    # Continue to collect items after this one
                    continue
                if feed.last_item_id is None or new_items or item["guid"] != feed.last_item_id:
                    new_items.append(item)

            # If no last_item_id, post only the newest item to avoid flooding on first run
            if feed.last_item_id is None:
                new_items = [items[0]] if items else []

            for item in new_items:
                parts = []
                if item["title"]:
                    parts.append(f"📰 {item['title']}")
                if item["summary"]:
                    summary = item["summary"][:500]
                    parts.append(summary)
                if item["link"]:
                    parts.append(item["link"])
                text = "\n\n".join(parts) or item.get("guid", "")
                if text:
                    try:
                        await _post_channel_message(feed.room_id, text, db)
                    except Exception as e:
                        logger.warning("Failed to post RSS item to channel %s: %s", feed.room_id, e)

            # Update last_item_id to newest item
            if items:
                feed.last_item_id = items[0]["guid"]
            feed.last_fetched = datetime.now(timezone.utc)

            try:
                db.commit()
            except Exception as e:
                logger.warning("DB commit failed updating feed %s: %s", feed.id, e)
                db.rollback()
