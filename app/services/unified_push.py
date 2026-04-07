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
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Shared pool for UP delivery
_up_pool = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, connect=3.0),
    limits=httpx.Limits(max_keepalive_connections=5, max_connections=20),
    verify=True,
)


@dataclass
class UPSubscription:
    """UnifiedPush subscription for a user."""
    user_id:    int
    endpoint:   str           # UP distributor endpoint URL
    app_id:     str = "org.vortex.messenger"
    created_at: float = field(default_factory=time.time)
    failures:   int   = 0
    active:     bool  = True


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

    def __init__(self):
        self._subs: dict[int, list[UPSubscription]] = {}  # user_id → subscriptions

    async def register(self, user_id: int, endpoint: str, app_id: str = "org.vortex.messenger") -> UPSubscription:
        """Register a UnifiedPush endpoint for a user."""
        # Validate endpoint URL
        if not endpoint.startswith(("https://", "http://localhost")):
            raise ValueError("UP endpoint must use HTTPS")

        sub = UPSubscription(user_id=user_id, endpoint=endpoint, app_id=app_id)

        if user_id not in self._subs:
            self._subs[user_id] = []

        # Replace existing subscription with same endpoint
        self._subs[user_id] = [s for s in self._subs[user_id] if s.endpoint != endpoint]
        self._subs[user_id].append(sub)

        logger.info("UP subscription registered: user=%d endpoint=%s", user_id, endpoint[:50])
        return sub

    async def unregister(self, user_id: int, endpoint: str) -> bool:
        """Remove a UnifiedPush subscription."""
        subs = self._subs.get(user_id, [])
        before = len(subs)
        self._subs[user_id] = [s for s in subs if s.endpoint != endpoint]
        return len(self._subs.get(user_id, [])) < before

    async def send(self, user_id: int, encrypted_payload: bytes) -> bool:
        """
        Send encrypted push notification via UnifiedPush.

        Payload is already encrypted by caller (sealed_push.py).
        We just POST raw bytes to the UP endpoint.
        """
        subs = self._subs.get(user_id, [])
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

            # Disable after 15 consecutive failures
            if sub.failures >= 15:
                sub.active = False
                logger.warning("UP subscription disabled (15 failures): user=%d", user_id)

        return delivered

    def get_subscriptions(self, user_id: int) -> list[dict]:
        """List active UP subscriptions for a user."""
        return [
            {
                "endpoint": s.endpoint[:60] + "..." if len(s.endpoint) > 60 else s.endpoint,
                "app_id":   s.app_id,
                "active":   s.active,
                "failures": s.failures,
            }
            for s in self._subs.get(user_id, [])
        ]

    def has_subscription(self, user_id: int) -> bool:
        """Check if user has any active UP subscription."""
        return any(s.active for s in self._subs.get(user_id, []))

    def stats(self) -> dict:
        total = sum(len(v) for v in self._subs.values())
        active = sum(1 for subs in self._subs.values() for s in subs if s.active)
        return {"total": total, "active": active, "users": len(self._subs)}


# Global instance
up_manager = UnifiedPushManager()
