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

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.push import push_registry_backend as _registry
from app.security import ratelimit_backend as _ratelimit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/push-proxy", tags=["bmp-push-proxy"])


CATEGORY_COUNT = 256  # Number of push categories (k-anonymity buckets)

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
    "push.services.mozilla.com",  # Firefox / autopush
    "fcm.googleapis.com",  # Chrome / Android (FCM)
    "android.googleapis.com",  # legacy GCM/FCM
    "web.push.apple.com",  # Safari / Apple Web Push
    "notify.windows.com",  # Edge / WNS
    "wns2-by3p.notify.windows.com",
)

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _allow_register(request: Request) -> None:
    if not _ratelimit.push_register_allowed(_client_ip(request)):
        raise HTTPException(429, "Rate limit exceeded")


def _allow_wake(request: Request) -> None:
    if not _ratelimit.push_wake_allowed(_client_ip(request)):
        raise HTTPException(429, "Rate limit exceeded")


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
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
                or addr.is_unspecified
            ):
                return False
            if str(addr).startswith("169.254."):
                return False
    except (socket.gaierror, ValueError):
        return False
    return True


async def _wake_category(category: int) -> None:
    """
    Handle wake signal from mailbox server.
    Send push notification to all tokens in this category.
    """
    addressed = await asyncio.to_thread(_registry.wake, category)
    if not addressed:
        return

    # Send push to each token (fire-and-forget)
    for endpoint, token in addressed:
        with contextlib.suppress(Exception):
            await _send_push(endpoint, token)

    logger.debug("[PushProxy] Wake category=%d → %d tokens", category, len(addressed))


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

        private_key, _public_key = _get_vapid_key_pair()
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


class ProxyRegisterRequest(BaseModel):
    categories: list[int] = Field(..., min_length=1, max_length=256, description="Category numbers (0-255)")
    token: str = Field(..., min_length=10, description="Push subscription keys as JSON string")
    endpoint: str = Field(..., min_length=10, description="Web Push endpoint URL")


@router.post("/register")
async def proxy_register(body: ProxyRegisterRequest, request: Request):
    """
    Register push token for BMP categories.
    Anonymous by design (no user identity), but per-IP rate-limited and the
    endpoint is validated as a real Web Push provider host.
    Client computes categories = SHA256(mailbox_id) mod 256 for each room.
    """
    # FIX F11(d): per-IP rate limit to stop registration flooding.
    _allow_register(request)
    # FIX F11(b): reject endpoints that aren't real Web Push providers / resolve
    # internally, so a poisoned registration can never become an SSRF on wake.
    if not _endpoint_is_safe(body.endpoint):
        raise HTTPException(403, "Push endpoint not permitted")
    try:
        await asyncio.to_thread(_registry.register, body.categories, body.token, body.endpoint)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    return {"ok": True}


@router.post("/unregister")
async def proxy_unregister(body: dict, request: Request):
    """Unregister a push token."""
    # FIX F11(d): rate-limit alongside register (shares the register bucket).
    _allow_register(request)
    token = body.get("token", "")
    if token:
        with contextlib.suppress(ValueError):
            await asyncio.to_thread(_registry.unregister, token)
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
    secret_ok = bool(PUSH_WAKE_SECRET) and bool(provided) and hmac.compare_digest(provided, PUSH_WAKE_SECRET)

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
    _allow_wake(request)
    await _wake_category(body.category)
    return {"ok": True}


@router.get("/stats")
async def proxy_stats():
    """Push proxy statistics."""
    return await asyncio.to_thread(_registry.tally)


def compute_category(mailbox_id: str) -> int:
    """Compute push category from mailbox ID. SHA256(id) mod 256."""
    return hashlib.sha256(mailbox_id.encode()).digest()[0]
