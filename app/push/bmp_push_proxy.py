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
import hmac
import ipaddress
import logging
import os
import secrets
import socket
import time
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/push-proxy", tags=["bmp-push-proxy"])

# ── Configuration ────────────────────────────────────────────────────────────

CATEGORY_COUNT = 256                # Number of push categories (k-anonymity buckets)
TOKEN_TTL = 7 * 86400              # Push tokens expire after 7 days
MAX_TOKENS_PER_CATEGORY = 10000    # Prevent abuse

# FIX F11(a): /wake is an INTERNAL trigger (mailbox server → proxy). It must not
# be callable by arbitrary clients, or anyone could fan out push wakes for any
# category. Authenticate it with a shared secret AND/OR restrict it to loopback.
# The secret is read from the env; if unset we fall back to loopback-only so the
# endpoint is never silently open to the network.
PUSH_WAKE_SECRET = os.getenv("BMP_PUSH_WAKE_SECRET", "").strip()
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

# FIX F11(b): only allow registering Web Push endpoints on real provider hosts.
# Anything else (and any host resolving to an internal/reserved IP) is rejected
# BEFORE webpush() is ever called, so the proxy can't be used as an SSRF sink.
ALLOWED_PUSH_HOST_SUFFIXES = (
    "push.services.mozilla.com",     # Firefox / autopush
    "fcm.googleapis.com",            # Chrome / Android (FCM)
    "android.googleapis.com",        # legacy GCM/FCM
    "web.push.apple.com",            # Safari / Apple Web Push
    "notify.windows.com",            # Edge / WNS
    "wns2-by3p.notify.windows.com",
)

# FIX F11(a,d): per-IP rate limits on register/wake (in-memory sliding window).
_REGISTER_RATE_LIMIT = 60          # registrations / window per IP
_WAKE_RATE_LIMIT = 600             # wake triggers / window per IP
_RATE_WINDOW = 60                  # seconds
_register_hits: dict[str, list[float]] = defaultdict(list)
_wake_hits: dict[str, list[float]] = defaultdict(list)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_limit(bucket: dict, key: str, limit: int) -> None:
    now = time.time()
    cutoff = now - _RATE_WINDOW
    bucket[key] = [t for t in bucket[key] if t > cutoff]
    if len(bucket[key]) >= limit:
        raise HTTPException(429, "Rate limit exceeded")
    bucket[key].append(now)


def _endpoint_is_safe(endpoint: str) -> bool:
    """
    FIX F11(b): validate a Web Push endpoint before we ever hand it to webpush().
      - must be https
      - host must belong to a known Web Push provider
      - host must NOT resolve to an internal/private/reserved IP (SSRF guard,
        mirroring app.chats.link_preview._is_internal_host)
    """
    try:
        parsed = urlparse(endpoint)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if not any(host == s or host.endswith("." + s) for s in ALLOWED_PUSH_HOST_SUFFIXES):
        return False
    # Resolve and reject any internal/reserved address (defence-in-depth: a
    # provider host should never resolve internally, but never trust it blindly).
    try:
        for info in socket.getaddrinfo(host, None):
            addr = ipaddress.ip_address(info[4][0])
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
                return False
            if str(addr).startswith("169.254."):
                return False
    except (socket.gaierror, ValueError):
        return False
    return True


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
        # FIX F11(b): never push to an endpoint we haven't re-validated as a real
        # Web Push provider that resolves to a public IP — closes the SSRF sink.
        if not _endpoint_is_safe(endpoint):
            logger.debug("[PushProxy] Rejected unsafe push endpoint")
            return

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
async def proxy_register(body: ProxyRegisterRequest, request: Request):
    """
    Register push token for BMP categories.
    Anonymous by design (no user identity), but per-IP rate-limited and the
    endpoint is validated as a real Web Push provider host.
    Client computes categories = SHA256(mailbox_id) mod 256 for each room.
    """
    # FIX F11(d): per-IP rate limit to stop registration flooding.
    _rate_limit(_register_hits, _client_ip(request), _REGISTER_RATE_LIMIT)
    # FIX F11(b): reject endpoints that aren't real Web Push providers / resolve
    # internally, so a poisoned registration can never become an SSRF on wake.
    if not _endpoint_is_safe(body.endpoint):
        raise HTTPException(403, "Push endpoint not permitted")
    push_proxy.register(body.categories, body.token, body.endpoint)
    return {"ok": True}


@router.post("/unregister")
async def proxy_unregister(body: dict, request: Request):
    """Unregister a push token."""
    # FIX F11(d): rate-limit alongside register (shares the register bucket).
    _rate_limit(_register_hits, _client_ip(request), _REGISTER_RATE_LIMIT)
    token = body.get("token", "")
    if token:
        push_proxy.unregister(token)
    return {"ok": True}


class WakeRequest(BaseModel):
    category: int = Field(..., ge=0, lt=CATEGORY_COUNT)


def _authorize_wake(request: Request) -> None:
    """
    FIX F11(a): /wake is an internal trigger. Accept it only when EITHER the
    caller presents the shared secret (constant-time compared) OR the request
    originates from loopback. If a secret is configured it is required for
    non-loopback callers; if no secret is configured, only loopback is allowed.
    """
    peer = request.client.host if request.client else ""
    is_loopback = peer in _LOOPBACK_HOSTS

    provided = (request.headers.get("x-push-wake-secret", "") or "").strip()
    secret_ok = bool(PUSH_WAKE_SECRET) and bool(provided) and \
        hmac.compare_digest(provided, PUSH_WAKE_SECRET)

    if secret_ok or is_loopback:
        return
    raise HTTPException(403, "Forbidden")


@router.post("/wake")
async def proxy_wake(body: WakeRequest, request: Request):
    """
    Called by mailbox server when a new message is deposited.
    Sends push to all tokens in the given category.
    Internal endpoint — authenticated (shared secret / loopback) and rate-limited.
    """
    # FIX F11(a): authenticate as an internal trigger before doing any work.
    _authorize_wake(request)
    # FIX F11(d): per-IP rate limit on wake fan-out.
    _rate_limit(_wake_hits, _client_ip(request), _WAKE_RATE_LIMIT)
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
