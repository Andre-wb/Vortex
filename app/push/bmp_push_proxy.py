"""
app/push/bmp_push_proxy.py — Anonymous Push Proxy for BMP

Architecture (from RESEARCH-BMP.md section 4.2):
  - Mailbox server emits anonymous "wake" signal with category = SHA256(mailbox_id) mod 256
  - Push proxy stores {category -> [push_tokens]}, does NOT know mailbox_id
  - Mailbox server knows mailbox_id but does NOT know push_tokens
  - Neither component has the full picture

Client registration:
  1. Client derives their mailbox IDs for all rooms
  2. Client computes categories = SHA256(mailbox_id) mod 256 for each
  3. Client registers push_token with proxy for those categories
  4. When server deposits into a mailbox, it emits wake(category)
  5. Proxy sends push to all tokens registered for that category
  6. Client receives push, polls BMP, gets new messages

Privacy guarantees:
  - Push proxy cannot link push_token to mailbox_id (only knows category 0-255)
  - Mailbox server cannot link mailbox_id to push_token (only emits category)
  - Each category covers ~N_users/256 users, providing k-anonymity
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/push-proxy", tags=["bmp-push-proxy"])

# ── Configuration ────────────────────────────────────────────────────────────

CATEGORY_COUNT = 256                # Number of push categories (k-anonymity buckets)
TOKEN_TTL = 7 * 86400              # Push tokens expire after 7 days
MAX_TOKENS_PER_CATEGORY = 10000    # Prevent abuse


# ── In-memory store ──────────────────────────────────────────────────────────

@dataclass
class PushRegistration:
    token: str
    endpoint: str       # Web Push endpoint URL
    registered_at: float


class PushProxyStore:
    """
    Maps category (0-255) -> list of push registrations.
    Completely anonymous — no user IDs, no mailbox IDs.
    """

    def __init__(self):
        self._categories: dict[int, list[PushRegistration]] = defaultdict(list)
        self._total_wakes = 0

    def register(self, categories: list[int], token: str, endpoint: str):
        """Register push token for given categories."""
        now = time.time()
        reg = PushRegistration(token=token, endpoint=endpoint, registered_at=now)
        for cat in categories:
            cat = cat % CATEGORY_COUNT
            # Dedup
            self._categories[cat] = [r for r in self._categories[cat] if r.token != token]
            if len(self._categories[cat]) < MAX_TOKENS_PER_CATEGORY:
                self._categories[cat].append(reg)

    def unregister(self, token: str):
        """Remove push token from all categories."""
        for cat in list(self._categories.keys()):
            self._categories[cat] = [r for r in self._categories[cat] if r.token != token]

    def get_tokens_for_category(self, category: int) -> list[PushRegistration]:
        """Get all registrations for a category. Used by wake signal handler."""
        now = time.time()
        cat = category % CATEGORY_COUNT
        # Remove expired
        self._categories[cat] = [r for r in self._categories[cat] if now - r.registered_at < TOKEN_TTL]
        return self._categories[cat]

    async def wake(self, category: int):
        """
        Handle wake signal from mailbox server.
        Send push notification to all tokens in this category.
        """
        self._total_wakes += 1
        tokens = self.get_tokens_for_category(category)
        if not tokens:
            return

        # Send push to each token (fire-and-forget)
        for reg in tokens:
            try:
                await _send_push(reg.endpoint, reg.token)
            except Exception:
                pass

        logger.debug("[PushProxy] Wake category=%d → %d tokens", category, len(tokens))

    def stats(self) -> dict:
        total_tokens = sum(len(v) for v in self._categories.values())
        active_cats = sum(1 for v in self._categories.values() if v)
        return {
            "total_tokens": total_tokens,
            "active_categories": active_cats,
            "total_wakes": self._total_wakes,
        }


push_proxy = PushProxyStore()


# ── Push sending (Web Push API) ─────────────────────────────────────────────

async def _send_push(endpoint: str, token: str):
    """
    Send a minimal "wake up and poll BMP" push notification.
    The payload is intentionally empty — no content, no metadata.
    Just a signal to the service worker to start polling.
    """
    try:
        from app.push.web_push import _get_vapid_key_pair
        private_key, public_key = _get_vapid_key_pair()
        if not private_key:
            return

        # Minimal payload: just {"type": "bmp_wake"}
        import json
        from pywebpush import webpush
        webpush(
            subscription_info={"endpoint": endpoint, "keys": json.loads(token)},
            data=json.dumps({"type": "bmp_wake"}),
            vapid_private_key=private_key,
            vapid_claims={"sub": "mailto:push@vortex.local"},
            timeout=5,
        )
    except Exception as e:
        logger.debug("[PushProxy] Push failed: %s", e)


# ── API Endpoints ────────────────────────────────────────────────────────────

class ProxyRegisterRequest(BaseModel):
    categories: list[int] = Field(..., min_length=1, max_length=256,
                                   description="Category numbers (0-255)")
    token: str = Field(..., min_length=10,
                       description="Push subscription keys as JSON string")
    endpoint: str = Field(..., min_length=10,
                          description="Web Push endpoint URL")


@router.post("/register")
async def proxy_register(body: ProxyRegisterRequest):
    """
    Register push token for BMP categories.
    No authentication — anonymous by design.
    Client computes categories = SHA256(mailbox_id) mod 256 for each room.
    """
    push_proxy.register(body.categories, body.token, body.endpoint)
    return {"ok": True}


@router.post("/unregister")
async def proxy_unregister(body: dict):
    """Unregister a push token."""
    token = body.get("token", "")
    if token:
        push_proxy.unregister(token)
    return {"ok": True}


class WakeRequest(BaseModel):
    category: int = Field(..., ge=0, lt=CATEGORY_COUNT)


@router.post("/wake")
async def proxy_wake(body: WakeRequest):
    """
    Called by mailbox server when a new message is deposited.
    Sends push to all tokens in the given category.
    Internal endpoint — should be called only by the BMP store.
    """
    await push_proxy.wake(body.category)
    return {"ok": True}


@router.get("/stats")
async def proxy_stats():
    """Push proxy statistics."""
    return push_proxy.stats()


# ── Helper for mailbox server integration ────────────────────────────────────

def compute_category(mailbox_id: str) -> int:
    """Compute push category from mailbox ID. SHA256(id) mod 256."""
    return hashlib.sha256(mailbox_id.encode()).digest()[0]
