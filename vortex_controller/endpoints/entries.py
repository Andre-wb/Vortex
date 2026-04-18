"""GET /v1/entries — signed list of bootstrap entry URLs.

Entry URLs are pre-configured (via ENTRY_URLS env var or entries.txt file);
they're meant to be the "first hop" for clients that can't reach the
controller domain directly (e.g. users behind domain-level censorship).

The list is signed with the controller's Ed25519 key; clients verify the
signature against the pinned controller pubkey.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Request

from ..controller_crypto import sign_response

router = APIRouter(prefix="/v1", tags=["entries"])

# Entries are considered fresh for this long (client may refresh sooner)
ENTRIES_TTL_SEC = 3600


@router.get("/entries")
async def entries(request: Request) -> dict:
    entry_urls: list[str] = request.app.state.entry_urls
    key = request.app.state.controller_key
    now = int(time.time())

    payload = {
        "entries": [{"url": u, "type": _classify(u)} for u in entry_urls],
        "issued_at": now,
        "valid_until": now + ENTRIES_TTL_SEC,
    }
    return sign_response(key, payload)


def _classify(url: str) -> str:
    """Rough classification so clients can prefer transport types."""
    low = url.lower()
    if low.endswith(".onion") or ".onion/" in low or ".onion:" in low:
        return "tor"
    if low.startswith("ipfs://") or low.startswith("ipns://"):
        return "ipfs"
    if "trycloudflare.com" in low or ".cfargotunnel.com" in low:
        return "tunnel"
    if low.startswith("wss://") or low.startswith("https://"):
        return "direct"
    return "unknown"
