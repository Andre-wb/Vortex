"""Request-level gate that refuses to serve a tampered controller.

If the startup integrity check fails (``tampered`` / ``bad_signature`` /
``wrong_key``) we don't want clients to keep using this instance — they'd
be trusting a pubkey on code that's been modified.

Instead, every protected endpoint returns HTTP 503 with:

    {
        "error": "integrity_failed",
        "status": "tampered",
        "message": "…",
        "integrity_url": "/v1/integrity"
    }

Endpoints that MUST stay reachable regardless of status:
    /                      — the website (shows red badge so operator sees it)
    /v1/health             — so monitoring can tell the node is alive but bad
    /v1/integrity          — so clients can diagnose exactly why they were refused
    /static/...            — website assets
    /favicon.ico
    /locales/...           — locale JSONs (served by the website)

Everything else — register, heartbeat, nodes/random, entries, mirrors —
is blocked, so a compromised controller cannot issue signed responses
that would be trusted in a regular flow.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# Prefixes that remain accessible even on a tampered build.
# Keep this list tight — every item here is a potential info-leak surface.
_SAFE_PREFIXES = (
    "/v1/health",
    "/v1/integrity",
    "/v1/treasury",   # public fee schedule — independent of registry state
    "/static/",
    "/locales/",
    "/favicon",
)

# Exact paths that are always safe.
_SAFE_EXACT = {
    "/", "",
    "/INTEGRITY.sig.json",
    "/nodes", "/entries", "/mirrors", "/security",
}


def _path_is_safe(path: str) -> bool:
    if path in _SAFE_EXACT:
        return True
    for p in _SAFE_PREFIXES:
        if path.startswith(p):
            return True
    return False


_FAILING_STATUSES = frozenset({"tampered", "bad_signature", "wrong_key"})


class IntegrityGateMiddleware(BaseHTTPMiddleware):
    """Refuses protected endpoints if ``app.state.integrity`` is in a bad state."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        report = getattr(request.app.state, "integrity", None)
        if report is not None and report.status in _FAILING_STATUSES:
            if not _path_is_safe(request.url.path):
                return JSONResponse(
                    status_code=503,
                    headers={
                        "X-Vortex-Integrity": report.status,
                        "Retry-After": "0",
                    },
                    content={
                        "error": "integrity_failed",
                        "status": report.status,
                        "message": report.message,
                        "integrity_url": "/v1/integrity",
                    },
                )
        return await call_next(request)
