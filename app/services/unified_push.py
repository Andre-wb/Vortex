"""
app/services/unified_push.py — UnifiedPush (UP) endpoint.

Open standard for push notifications without Google/Apple dependency.
Supports any UP distributor (ntfy, NextPush, Conversations, etc.).

Spec: https://unifiedpush.org/spec/

Flow:
  1. Client registers with a UP distributor (e.g. ntfy.sh)
  2. Client sends UP endpoint URL to Vortex server
  3. Vortex POSTs encrypted payload to UP endpoint
  4. UP distributor delivers to client app
  5. Client decrypts payload locally

No FCM/APNs required — works on de-Googled phones (GrapheneOS, CalyxOS, LineageOS).

Подписки живут в таблице `unified_push_subscriptions`: доставить пуш должен
любой воркер, а не только принявший регистрацию.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import UnifiedPushSubscription

logger = logging.getLogger(__name__)

MAX_FAILURES = 15

_up_pool = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, connect=3.0),
    limits=httpx.Limits(max_keepalive_connections=5, max_connections=20),
    verify=True,
)


class UnifiedPushManager:
    """
    Manages UnifiedPush subscriptions and delivery.

    Differences from Web Push VAPID:
      - No browser vendor dependency (no FCM/APNs)
      - Works on de-Googled Android (GrapheneOS, CalyxOS)
      - Any UP-compatible distributor (ntfy, NextPush, Conversations)
      - Simple HTTP POST to endpoint
      - Payload encrypted client-side (E2E)
    """

    async def register(
        self,
        db: Session,
        user_id: int,
        endpoint: str,
        app_id: str = "org.vortex.messenger",
    ) -> UnifiedPushSubscription:
        """Register a UnifiedPush endpoint for a user."""
        if not endpoint.startswith(("https://", "http://localhost")):
            raise ValueError("UP endpoint must use HTTPS")

        sub = self._find(db, user_id, endpoint)
        if sub:
            sub.app_id = app_id
            sub.failures = 0
            sub.active = True
            sub.created_at = datetime.now(timezone.utc)
        else:
            sub = UnifiedPushSubscription(user_id=user_id, endpoint=endpoint, app_id=app_id)
            db.add(sub)
        db.commit()
        db.refresh(sub)

        logger.info("UP subscription registered: user=%d endpoint=%s", user_id, endpoint[:50])
        return sub

    async def unregister(self, db: Session, user_id: int, endpoint: str) -> bool:
        """Remove a UnifiedPush subscription."""
        removed = (
            db.query(UnifiedPushSubscription)
            .filter(
                UnifiedPushSubscription.user_id == user_id,
                UnifiedPushSubscription.endpoint == endpoint,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        return bool(removed)

    async def send(self, user_id: int, encrypted_payload: bytes) -> bool:
        """
        Send encrypted push notification via UnifiedPush.

        Payload is already encrypted by caller.
        We just POST raw bytes to the UP endpoint.
        """
        db = SessionLocal()
        try:
            subs = self._of_user(db, user_id)
            if not subs:
                return False

            delivered = False
            for sub in subs:
                if not sub.active:
                    continue
                try:
                    r = await _up_pool.post(
                        sub.endpoint,
                        content=encrypted_payload,
                        headers={
                            "Content-Type": "application/octet-stream",
                            "TTL": "86400",
                        },
                    )
                    if r.status_code < 400:
                        sub.failures = 0
                        delivered = True
                    else:
                        sub.failures += 1
                        logger.debug("UP delivery failed: HTTP %d endpoint=%s", r.status_code, sub.endpoint[:50])
                except Exception as e:
                    sub.failures += 1
                    logger.debug("UP delivery error: %s endpoint=%s", str(e)[:100], sub.endpoint[:50])

                if sub.failures >= MAX_FAILURES:
                    sub.active = False
                    logger.warning("UP subscription disabled (%d failures): user=%d", MAX_FAILURES, user_id)
            db.commit()
            return delivered
        finally:
            db.close()

    def get_subscriptions(self, db: Session, user_id: int) -> list[dict]:
        """List active UP subscriptions for a user."""
        return [
            {
                "endpoint": s.endpoint[:60] + "..." if len(s.endpoint) > 60 else s.endpoint,
                "app_id": s.app_id,
                "active": s.active,
                "failures": s.failures,
            }
            for s in self._of_user(db, user_id)
        ]

    def has_subscription(self, db: Session, user_id: int) -> bool:
        """Check if user has any active UP subscription."""
        return any(s.active for s in self._of_user(db, user_id))

    def stats(self, db: Session) -> dict:
        rows = db.query(UnifiedPushSubscription).all()
        return {
            "total": len(rows),
            "active": sum(1 for row in rows if row.active),
            "users": len({row.user_id for row in rows}),
        }

    def _find(self, db: Session, user_id: int, endpoint: str) -> UnifiedPushSubscription | None:
        return (
            db.query(UnifiedPushSubscription)
            .filter(
                UnifiedPushSubscription.user_id == user_id,
                UnifiedPushSubscription.endpoint == endpoint,
            )
            .first()
        )

    def _of_user(self, db: Session, user_id: int) -> list[UnifiedPushSubscription]:
        return (
            db.query(UnifiedPushSubscription)
            .filter(UnifiedPushSubscription.user_id == user_id)
            .order_by(UnifiedPushSubscription.id)
            .all()
        )


up_manager = UnifiedPushManager()
