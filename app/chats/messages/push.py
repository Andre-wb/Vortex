"""
app/chats/chat_push.py — Web Push subscriptions and notification delivery.
"""
from __future__ import annotations

import json
import logging

from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.chats.messages._router import router
from app.config import Config
from app.database import get_db
from app.models import PushSubscription, User
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)


class _PushSubscribeRequest(BaseModel):
    endpoint: str
    keys: dict  # {p256dh: str, auth: str}


@router.post("/api/push/subscribe")
async def push_subscribe(
    body: _PushSubscribeRequest,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Сохраняет push-подписку пользователя."""
    existing = db.query(PushSubscription).filter(
        PushSubscription.endpoint == body.endpoint,
    ).first()
    if existing:
        existing.user_id = u.id
        existing.p256dh  = body.keys.get("p256dh", "")
        existing.auth    = body.keys.get("auth", "")
    else:
        db.add(PushSubscription(
            user_id  = u.id,
            endpoint = body.endpoint,
            p256dh   = body.keys.get("p256dh", ""),
            auth     = body.keys.get("auth", ""),
        ))
    db.commit()
    return {"ok": True}


async def send_web_push(
    user_id: int,
    sender_name: str,
    room_id: int,
    is_dm: bool,
    db: Session,
) -> None:
    """Send Web Push notification to an offline user. Silently ignores failures."""
    try:
        from pywebpush import webpush, WebPushException
    except ImportError:
        return

    vapid_priv = Config.VAPID_PRIVATE_KEY
    if not vapid_priv:
        return

    if "|" in vapid_priv and "BEGIN" in vapid_priv:
        vapid_priv = vapid_priv.replace("|", "\n")

    subs = db.query(PushSubscription).filter(PushSubscription.user_id == user_id).all()
    for sub in subs:
        try:
            webpush(
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
                },
                data=json.dumps({
                    "title":   sender_name,
                    "body":    "Личное сообщение" if is_dm else "Новое сообщение",
                    "room_id": room_id,
                }),
                vapid_private_key=vapid_priv,
                vapid_claims={"sub": "mailto:noreply@vortex.local"},
            )
        except (Exception,) as e:
            logger.debug("Web push failed for user %s sub %s: %s — removing subscription", user_id, sub.endpoint[:30], e)
            try:
                db.delete(sub)
                db.commit()
            except Exception:
                db.rollback()
