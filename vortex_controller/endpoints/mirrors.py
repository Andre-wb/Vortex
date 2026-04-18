"""GET /v1/mirrors — signed list of alternative addresses.

Operators configure MIRROR_URLS (comma-separated). Use cases:
    - IPFS pin of the same web bundle
    - .onion mirror
    - Alternative domain name
    - Raw IP if DNS is blocked

Clients display these at the bottom of the page: "If this site is blocked,
try: ..." — with a health indicator next to each.

The signed payload now carries per-mirror health data produced by
``MirrorHealthChecker`` so clients don't need a separate call.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Request

from ..controller_crypto import sign_response

router = APIRouter(prefix="/v1", tags=["mirrors"])

MIRRORS_TTL_SEC = 86400


@router.get("/mirrors")
async def mirrors(request: Request) -> dict:
    urls: list[str] = request.app.state.mirror_urls
    key = request.app.state.controller_key
    checker = getattr(request.app.state, "mirror_health", None)

    now = int(time.time())

    entries = []
    for url in urls:
        entry = {"url": url, "type": _classify(url)}
        if checker is not None:
            st = checker.state.by_url.get(url)
            if st is not None:
                entry["healthy"] = st.ok
                entry["latency_ms"] = st.latency_ms
                entry["last_checked"] = int(st.last_checked) if st.last_checked else 0
                if not st.ok and st.error:
                    entry["error"] = st.error
        entries.append(entry)

    payload = {
        "mirrors": entries,
        "issued_at": now,
        "valid_until": now + MIRRORS_TTL_SEC,
    }
    return sign_response(key, payload)


@router.get("/mirrors/health")
async def mirrors_health(request: Request) -> dict:
    """Unsigned shortcut for the website — health snapshot only."""
    checker = getattr(request.app.state, "mirror_health", None)
    if checker is None:
        return {"last_sweep": 0, "mirrors": []}
    return checker.state.snapshot()


def _classify(url: str) -> str:
    low = url.lower()
    if ".onion" in low:
        return "tor"
    if low.startswith("ipfs://") or low.startswith("ipns://") or ".ipfs." in low:
        return "ipfs"
    return "web"
