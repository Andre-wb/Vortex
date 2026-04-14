"""
app/push/web_push.py -- VAPID Web Push notifications.

Endpoints:
  POST /api/push/subscribe    -- save push subscription (endpoint, p256dh, auth)
  POST /api/push/unsubscribe  -- remove push subscription
  GET  /api/push/vapid-key    -- return public VAPID key for client

Helper:
  send_push(user_id, payload) -- deliver push notification via pywebpush
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.models import User
from app.models.media import PushSubscription
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/push", tags=["push"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class SubscribeRequest(BaseModel):
    endpoint: str
    p256dh: str
    auth: str


class UnsubscribeRequest(BaseModel):
    endpoint: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/vapid-key")
async def vapid_public_key(user: User = Depends(get_current_user)):
    """Return the server's VAPID public key so the client can subscribe."""
    pub = Config.VAPID_PUBLIC_KEY
    if not pub:
        raise HTTPException(503, "VAPID keys not configured")
    return {"public_key": pub}


@router.post("/subscribe")
async def subscribe(
    body: SubscribeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Save or update a push subscription for the current user."""
    existing = (
        db.query(PushSubscription)
        .filter(PushSubscription.endpoint == body.endpoint)
        .first()
    )
    if existing:
        existing.user_id = user.id
        existing.p256dh = body.p256dh
        existing.auth = body.auth
    else:
        sub = PushSubscription(
            user_id=user.id,
            endpoint=body.endpoint,
            p256dh=body.p256dh,
            auth=body.auth,
        )
        db.add(sub)
    db.commit()
    return {"ok": True}


@router.post("/unsubscribe")
async def unsubscribe(
    body: UnsubscribeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove a push subscription."""
    deleted = (
        db.query(PushSubscription)
        .filter(
            PushSubscription.user_id == user.id,
            PushSubscription.endpoint == body.endpoint,
        )
        .delete()
    )
    db.commit()
    return {"ok": True, "deleted": deleted}


# ---------------------------------------------------------------------------
# send_push -- deliver Web Push notification to a user
# ---------------------------------------------------------------------------

def _get_vapid_claims() -> dict:
    return {
        "sub": "mailto:admin@vortex.local",
    }


def send_push(user_id: int, payload: dict, db: Optional[Session] = None) -> int:
    """
    Send a Web Push notification to all subscriptions of *user_id*.

    Returns the number of successfully delivered notifications.
    Uses pywebpush if available; silently skips otherwise.
    """
    try:
        from pywebpush import webpush, WebPushException  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("pywebpush not installed -- skipping Web Push delivery")
        return 0

    priv_key = Config.VAPID_PRIVATE_KEY
    if not priv_key:
        logger.debug("VAPID_PRIVATE_KEY not set -- skipping Web Push")
        return 0

    # Restore PEM newlines (stored as | in .env)
    if "|" in priv_key:
        priv_key = priv_key.replace("|", "\n")

    close_db = False
    if db is None:
        from app.database import SessionLocal
        db = SessionLocal()
        close_db = True

    try:
        subs = (
            db.query(PushSubscription)
            .filter(PushSubscription.user_id == user_id)
            .all()
        )
        if not subs:
            return 0

        data_str = json.dumps(payload, ensure_ascii=False)
        sent = 0
        stale_ids: list[int] = []

        for sub in subs:
            subscription_info = {
                "endpoint": sub.endpoint,
                "keys": {
                    "p256dh": sub.p256dh,
                    "auth": sub.auth,
                },
            }
            try:
                webpush(
                    subscription_info=subscription_info,
                    data=data_str,
                    vapid_private_key=priv_key,
                    vapid_claims=_get_vapid_claims(),
                    ttl=86400,
                )
                sent += 1
            except WebPushException as exc:
                resp = getattr(exc, "response", None)
                status = getattr(resp, "status_code", 0) if resp else 0
                if status in (404, 410):
                    # Subscription expired/invalid -- schedule removal
                    stale_ids.append(sub.id)
                    logger.info("Push subscription expired (HTTP %s), removing id=%s", status, sub.id)
                else:
                    logger.warning("Web Push error for user %s: %s", user_id, exc)
            except Exception as exc:
                logger.warning("Web Push send error: %s", exc)

        # Cleanup stale subscriptions
        if stale_ids:
            db.query(PushSubscription).filter(PushSubscription.id.in_(stale_ids)).delete(
                synchronize_session=False
            )
            db.commit()

        return sent
    finally:
        if close_db:
            db.close()
