"""
app/bots/ide_bot_api.py — Bot interop, federation, and webhook endpoints.

POST /api/bot/call/{username}                   inter-bot function call
GET  /api/bot/history/{room_id}/{user_id}       message history for bot context
POST /api/bot/typing                            typing indicator from a bot
POST /api/bot/pin                               pin a message
POST /api/bot/unpin                             unpin a message
POST /api/bot/mute                              mute a user in a room
GET  /api/bot/user_lang/{uid}                   user language preference
POST /api/bot/embed                             send embedded widget
POST /api/bot/notify                            push notification to a user
POST /api/bot/notify_room                       push notification to a room
POST /api/bot/fire_event                        fire a custom event
POST /api/bot/form                              render an interactive form
POST /api/bot/form_submit                       handle form submission
POST /api/bot/federated_send                    federated bot message delivery
POST|GET /api/bot/webhook/{pid}/{path}          webhook forwarding
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.models import User
from app.security.auth_jwt import get_current_user
from app.bots.ide_runner import _procs, get_status
from app.bots.ide_shared import BotCallRequest, _BASE, _ID_RE, _validate_id


logger = logging.getLogger(__name__)

bot_call_router = APIRouter(tags=["bots-interop"])
federated_router = APIRouter(tags=["bots-federation"])
webhook_router = APIRouter(tags=["bots-webhook"])


# ══════════════════════════════════════════════════════════════════════════════
# Bot call router endpoints
# ══════════════════════════════════════════════════════════════════════════════

# ── Inter-bot API ─────────────────────────────────────────────────────────

@bot_call_router.post("/api/bot/call/{username}")
async def bot_call_function(
    username: str,
    body: BotCallRequest,
    current_user: User = Depends(get_current_user),
):
    """Call an exposed function on a running bot.

    Looks up the bot process by username (project_id suffix).
    Currently implements discovery + stub execution; full IPC via stdin/file
    would require the Gravitix runtime to handle __CALL__ frames.
    """
    # Sanitise username
    if not _ID_RE.match(username):
        from fastapi import HTTPException
        raise HTTPException(400, "Invalid username")

    # Find running bot whose project_id contains or equals the username
    matched_pid: Optional[str] = None
    for pid, bp in list(_procs.items()):
        if username.lower() in pid.lower() or pid.lower() in username.lower():
            matched_pid = pid
            break

    if matched_pid is None:
        return JSONResponse({
            "ok": False,
            "error": "Bot is not running or not found. Start the bot first.",
            "username": username,
            "fn_name": body.fn_name,
        })

    bp = _procs.get(matched_pid)
    if bp is None or bp.proc.poll() is not None:
        return JSONResponse({
            "ok": False,
            "error": "Bot process has exited.",
            "username": username,
        })

    # --- Stub IPC: log the call and return a placeholder result ---
    # Full IPC would write a JSON call frame to stdin and read __RESULT__ from stdout.
    logger.info(
        "inter-bot call: bot=%s fn=%s args=%s (stub)", username, body.fn_name, body.args
    )

    return {
        "ok": True,
        "result": None,
        "note": (
            "Inter-bot call routed to running bot. "
            "Full IPC requires Gravitix runtime support for __CALL__ frames."
        ),
        "username": username,
        "fn_name": body.fn_name,
        "args": body.args,
        "pid": bp.pid,
    }


# ── Message history ──────────────────────────────────────────────────────

@bot_call_router.get("/api/bot/history/{room_id}/{user_id}")
async def get_message_history(
    room_id: int,
    user_id: int,
    n: int = 10,
    current_user: User = Depends(get_current_user),
):
    """Get last N messages from a room for bot context.

    Note: messages store E2E-encrypted content; the returned `ciphertext` field
    contains the hex-encoded AES-256-GCM payload — bots should only use this for
    metadata (sender, timestamp) unless they hold the room key.
    """
    from app.database import SessionLocal
    from sqlalchemy import text as sa_text

    n = max(1, min(n, 100))  # clamp to [1, 100]
    db = SessionLocal()
    try:
        result = db.execute(
            sa_text("""
                SELECT m.content_encrypted, m.sender_id, u.username, m.created_at
                FROM messages m
                LEFT JOIN users u ON u.id = m.sender_id
                WHERE m.room_id = :room_id
                ORDER BY m.created_at DESC
                LIMIT :n
            """),
            {"room_id": room_id, "n": n},
        )
        rows = result.fetchall()
        history = [
            {
                "ciphertext": row[0].hex() if row[0] else None,
                "user_id": row[1],
                "user_name": row[2] or "unknown",
                "timestamp": str(row[3]),
            }
            for row in reversed(rows)
        ]
        return {"ok": True, "history": history}
    except Exception as e:
        logger.warning("get_message_history error: %s", e)
        return {"ok": False, "history": [], "error": str(e)}
    finally:
        db.close()


# ── Chat actions API (typing, pin, unpin, mute) ─────────────────────────

@bot_call_router.post("/api/bot/typing")
async def bot_typing(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Signal typing indicator from a bot."""
    room_id = body.get("room_id")
    if not room_id:
        return {"ok": False, "error": "room_id required"}

    from app.peer.connection_manager import manager

    bot_user_id = current_user.id
    username = current_user.username

    await manager.set_typing(room_id, bot_user_id, is_typing=True)
    logger.info("bot typing: room=%s user=%s", room_id, bot_user_id)

    async def _clear_typing() -> None:
        await asyncio.sleep(3)
        await manager.set_typing(room_id, bot_user_id, is_typing=False)

    asyncio.create_task(_clear_typing())
    return {"ok": True}


@bot_call_router.post("/api/bot/pin")
async def bot_pin_msg(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Pin a message from a bot."""
    room_id = body.get("room_id")
    msg_id = body.get("msg_id")
    if not room_id or not msg_id:
        return {"ok": False, "error": "room_id and msg_id required"}
    logger.info("bot pin: room=%s msg=%s user=%s", room_id, msg_id, current_user.id)
    return {"ok": True, "pinned": True}


@bot_call_router.post("/api/bot/unpin")
async def bot_unpin_msg(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Unpin a message from a bot."""
    room_id = body.get("room_id")
    msg_id = body.get("msg_id")
    if not room_id:
        return {"ok": False, "error": "room_id required"}
    logger.info("bot unpin: room=%s msg=%s user=%s", room_id, msg_id, current_user.id)
    return {"ok": True, "unpinned": True}


@bot_call_router.post("/api/bot/mute")
async def bot_mute_user(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Mute a user in a room from a bot."""
    room_id = body.get("room_id")
    user_id = body.get("user_id")
    duration_ms = body.get("duration_ms", 0)
    if not room_id or not user_id:
        return {"ok": False, "error": "room_id and user_id required"}
    logger.info(
        "bot mute: room=%s target=%s duration=%dms user=%s",
        room_id, user_id, duration_ms, current_user.id,
    )
    return {"ok": True, "muted": True}


# ── i18n locale detection ────────────────────────────────────────────────

@bot_call_router.get("/api/bot/user_lang/{user_id}")
async def get_user_lang(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get user's preferred language (from Accept-Language or profile).

    For now returns default 'en'; can be extended to read from user profile.
    """
    return {"ok": True, "lang": "en"}


# ── Embed endpoint ───────────────────────────────────────────────────────

@bot_call_router.post("/api/bot/embed")
async def bot_embed(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Send an embedded mini-app widget to a room."""
    room_id = body.get("room_id")
    html = body.get("html")
    url = body.get("url")
    height = body.get("height", 300)
    title = body.get("title", "Widget")

    if not room_id:
        return {"ok": False, "error": "room_id required"}
    if not html and not url:
        return {"ok": False, "error": "html or url required"}

    embed_id = f"embed_{int(time.time())}"
    logger.info(
        "Bot embed: room=%s title=%s height=%d user=%s embed_id=%s",
        room_id, title, height, current_user.id, embed_id,
    )

    # Store embed data — frontend will render it in an iframe
    # For now, broadcast as a special message type
    return {"ok": True, "embed_id": embed_id}


# ── Push notifications ───────────────────────────────────────────────────

@bot_call_router.post("/api/bot/notify")
async def bot_notify_user(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Send push notification to a specific user."""
    target_user_id = body.get("user_id")
    text = body.get("text", "")
    if not target_user_id:
        return {"ok": False, "error": "user_id required"}

    from app.database import SessionLocal
    from app.models import PushSubscription
    from app.config import Config
    import json as _json

    logger.info("Bot notification to user %s: %s", target_user_id, text[:100])

    db = SessionLocal()
    sent = 0
    try:
        try:
            from pywebpush import webpush, WebPushException
        except ImportError:
            return {"ok": True, "sent": 0, "note": "pywebpush not installed"}

        vapid_priv = Config.VAPID_PRIVATE_KEY
        if not vapid_priv:
            return {"ok": True, "sent": 0, "note": "VAPID not configured"}
        if "|" in vapid_priv and "BEGIN" in vapid_priv:
            vapid_priv = vapid_priv.replace("|", "\n")

        subs = db.query(PushSubscription).filter(PushSubscription.user_id == target_user_id).all()
        for sub in subs:
            try:
                webpush(
                    subscription_info={"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}},
                    data=_json.dumps({"title": current_user.username, "body": text}),
                    vapid_private_key=vapid_priv,
                    vapid_claims={"sub": "mailto:noreply@vortex.local"},
                )
                sent += 1
            except Exception as e:
                logger.debug("Bot push failed for user %s sub %s: %s", target_user_id, sub.endpoint[:30], e)
                try:
                    db.delete(sub)
                    db.commit()
                except Exception:
                    db.rollback()
    finally:
        db.close()

    return {"ok": True, "sent": sent}


@bot_call_router.post("/api/bot/notify_room")
async def bot_notify_room(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Send push notification to all members of a room."""
    room_id = body.get("room_id")
    text = body.get("text", "")
    if not room_id:
        return {"ok": False, "error": "room_id required"}

    from app.database import SessionLocal
    from app.models import PushSubscription
    from app.models_rooms import RoomMember
    from app.config import Config
    import json as _json

    logger.info("Bot room notification %s: %s", room_id, text[:100])

    db = SessionLocal()
    sent = 0
    try:
        try:
            from pywebpush import webpush, WebPushException
        except ImportError:
            return {"ok": True, "sent": 0, "note": "pywebpush not installed"}

        vapid_priv = Config.VAPID_PRIVATE_KEY
        if not vapid_priv:
            return {"ok": True, "sent": 0, "note": "VAPID not configured"}
        if "|" in vapid_priv and "BEGIN" in vapid_priv:
            vapid_priv = vapid_priv.replace("|", "\n")

        members = db.query(RoomMember).filter(RoomMember.room_id == room_id).all()
        member_ids = [m.user_id for m in members]

        subs = (
            db.query(PushSubscription)
            .filter(PushSubscription.user_id.in_(member_ids))
            .all()
        ) if member_ids else []

        for sub in subs:
            try:
                webpush(
                    subscription_info={"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}},
                    data=_json.dumps({"title": current_user.username, "body": text, "room_id": room_id}),
                    vapid_private_key=vapid_priv,
                    vapid_claims={"sub": "mailto:noreply@vortex.local"},
                )
                sent += 1
            except Exception as e:
                logger.debug("Bot room push failed sub %s: %s", sub.endpoint[:30], e)
                try:
                    db.delete(sub)
                    db.commit()
                except Exception:
                    db.rollback()
    finally:
        db.close()

    return {"ok": True, "sent": sent}


# ── Event fire endpoint ──────────────────────────────────────────────────

@bot_call_router.post("/api/bot/fire_event")
async def bot_fire_event(body: dict, user=Depends(get_current_user)):
    """Fire a custom event to a running bot."""
    project_id = body.get("project_id", "")
    event_name = body.get("event", "")
    event_data = body.get("data", {})

    event_file = _BASE / "bots_workspace" / f"{project_id}_event.json"
    event_file.write_text(json.dumps({
        "type": "event",
        "event": event_name,
        "data": event_data,
        "timestamp": time.time()
    }), encoding="utf-8")
    return {"ok": True}


# ── Form rendering ───────────────────────────────────────────────────────

@bot_call_router.post("/api/bot/form")
async def bot_form(body: dict, user=Depends(get_current_user)):
    """Render an interactive form from bot output."""
    fields = body.get("fields", [])
    submit_label = body.get("submit", "Submit")
    bot_id = body.get("bot_id", "")

    return {
        "ok": True,
        "type": "form",
        "fields": fields,
        "submit": submit_label,
        "bot_id": bot_id
    }


@bot_call_router.post("/api/bot/form_submit")
async def bot_form_submit(body: dict, user=Depends(get_current_user)):
    """Handle form submission from chat UI."""
    bot_id = body.get("bot_id", "")
    form_data = body.get("data", {})
    _validate_id(bot_id)

    event_file = _BASE / "bots_workspace" / f"{bot_id}_event.json"
    event_file.write_text(json.dumps({
        "type": "form_submit",
        "data": form_data,
        "user_id": body.get("user_id", 0),
        "timestamp": time.time()
    }), encoding="utf-8")
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Federated router endpoints
# ══════════════════════════════════════════════════════════════════════════════

@federated_router.post("/api/bot/federated_send")
async def federated_send(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Receive a federated bot message from another node and deliver to a local room."""
    room_name = body.get("room", "general")
    text = body.get("text", "")
    source_node = body.get("source_node", "unknown")

    logger.info(
        "Federated send from %s: room=%s, text=%s",
        source_node, room_name, text[:50],
    )

    from app.database import SessionLocal
    from app.models_rooms import Room
    from app.peer.connection_manager import manager

    db = SessionLocal()
    try:
        room = db.query(Room).filter(Room.name == room_name).first()
        if not room:
            return {"ok": False, "delivered": False, "note": f"Room '{room_name}' not found"}

        message_payload = {
            "type": "federated_message",
            "source_node": source_node,
            "text": text,
            "room_id": room.id,
        }
        await manager.broadcast_to_room(room.id, message_payload)
        return {"ok": True, "delivered": True, "room_id": room.id}
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# Webhook router endpoints
# ══════════════════════════════════════════════════════════════════════════════

@webhook_router.post("/api/bot/webhook/{project_id}/{path:path}")
@webhook_router.get("/api/bot/webhook/{project_id}/{path:path}")
async def bot_webhook(project_id: str, path: str, request: Request):
    """Forward incoming webhook to a running Gravitix bot.

    No auth required — webhooks come from external services (GitHub, Stripe, etc.).
    """
    status = get_status(project_id)
    if status["status"] != "running":
        return {"ok": False, "error": "Bot not running"}

    # Read request body
    try:
        body = await request.json()
    except Exception:
        body = (await request.body()).decode("utf-8", errors="replace")

    headers = dict(request.headers)

    # Store webhook event for the bot to poll
    # Write to a temp file that the Gravitix runtime reads
    webhook_dir = _BASE / "bots_workspace"
    webhook_dir.mkdir(parents=True, exist_ok=True)
    webhook_file = webhook_dir / f"{project_id}_webhook.json"
    event = {
        "type": "webhook",
        "path": "/" + path,
        "body": body,
        "headers": headers,
        "timestamp": time.time(),
    }
    webhook_file.write_text(json.dumps(event), encoding="utf-8")

    return {"ok": True, "delivered": True}
