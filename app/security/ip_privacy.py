"""
app/security/ip_privacy.py — Centralized IP address privacy layer.

All IP address capture in the codebase MUST go through `sanitize_ip(request)`
instead of reading `request.client.host` directly.

Behaviour depends on configuration:

  STORE_IPS=false          → always returns None (no IP stored anywhere)
  HASH_IPS=true            → returns HMAC-SHA256 of IP (rate-limiting works,
                              but real IP is irrecoverable without the secret)
  Tor / .onion connection  → returns "onion" (Tor exit IP is meaningless)
  Otherwise                → returns real IP (default, for abuse prevention)

The goal: when a privacy-conscious operator deploys Vortex with
``STORE_IPS=false`` and a Tor hidden service, there is ZERO IP
data in the database. Combined with Sealed Sender, the server
stores no identifying information about users or their messages.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from starlette.requests import Request

# ── Configuration (read once at import) ──────────────────────────────────────

_STORE_IPS: bool = os.environ.get("STORE_IPS", "true").lower() != "false"
_HASH_IPS:  bool = os.environ.get("HASH_IPS", "false").lower() == "true"

# HMAC key for IP hashing (derived from SECRET_KEY so hashes are stable
# within a deployment but irrecoverable without the key).
_HASH_KEY: bytes = hashlib.blake2b(
    os.environ.get("SECRET_KEY", "vortex-ip-hash-default").encode(),
    digest_size=32,
    person=b"ip-hash\x00\x00\x00\x00\x00\x00\x00\x00\x00",
).digest()

# Known Tor-related header values
_ONION_INDICATORS = frozenset({
    ".onion",
    "tor",
})


def _is_onion_request(request: Request) -> bool:
    """Detect if the request came through a Tor hidden service (.onion)."""
    # 1. Host header ends with .onion
    host = (request.headers.get("host") or "").lower()
    if host.endswith(".onion") or host.rstrip(":0123456789").endswith(".onion"):
        return True

    # 2. X-Tor header (set by Tor reverse proxy configs)
    if request.headers.get("x-tor", "").lower() in ("1", "true", "yes"):
        return True

    # 3. Onion-Location header present (server advertises .onion)
    if request.headers.get("onion-location"):
        return True

    return False


def _hash_ip(ip: str) -> str:
    """
    One-way HMAC-SHA256 of the IP address.

    The hash is deterministic within a deployment (same SECRET_KEY → same
    hash for same IP), so rate-limiting and duplicate detection still work.
    The real IP is irrecoverable without SECRET_KEY.

    Returns: 16-char hex prefix (enough for rate-limiting, short for storage).
    """
    return hmac.new(_HASH_KEY, ip.encode(), hashlib.sha256).hexdigest()[:16]


def sanitize_ip(request: Request) -> Optional[str]:
    """
    Extract and sanitize the client IP address from a request.

    This is the ONLY function that should be used to obtain IP addresses
    for storage in the database. Direct ``request.client.host`` access
    should be limited to in-memory rate-limiting (never persisted).

    Returns:
        - None           if STORE_IPS=false
        - "onion"        if request came via Tor hidden service
        - "h:<hash>"     if HASH_IPS=true (HMAC of real IP)
        - real IP        otherwise
    """
    if not _STORE_IPS:
        return None

    if _is_onion_request(request):
        return "onion"

    raw_ip = request.client.host if request.client else None
    if not raw_ip:
        return None

    if _HASH_IPS:
        return f"h:{_hash_ip(raw_ip)}"

    return raw_ip


def raw_ip_for_ratelimit(request: Request) -> str:
    """
    Get the real IP for in-memory rate-limiting (NOT for storage).

    Rate-limiting must always use the real IP, even when STORE_IPS=false,
    to prevent abuse. This value must NEVER be written to the database.
    """
    return request.client.host if request.client else "unknown"
