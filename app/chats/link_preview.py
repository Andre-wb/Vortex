"""
app/chats/link_preview.py — Open Graph link preview endpoint.

GET /api/link-preview?url=...
Fetches the target URL, parses OG meta tags, returns JSON preview data.
Uses in-memory LRU cache (max 500 entries) to avoid repeated fetches.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections import OrderedDict
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Query

# Separate reference so tests can patch this without affecting httpx globally
_AsyncClient = httpx.AsyncClient
from fastapi.responses import JSONResponse

from app.models import User
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["link-preview"])

# ── In-memory LRU cache ────────────────────────────────────────────────────
_CACHE_MAX = 500
_cache: OrderedDict[str, dict] = OrderedDict()


def _cache_get(url: str) -> Optional[dict]:
    if url in _cache:
        _cache.move_to_end(url)
        return _cache[url]
    return None


def _cache_set(url: str, data: dict) -> None:
    _cache[url] = data
    _cache.move_to_end(url)
    if len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)


# ── OG tag parsing ─────────────────────────────────────────────────────────
_OG_RE = re.compile(
    r'<meta\s[^>]*?'
    r'(?:property|name)\s*=\s*["\']og:(\w+)["\']'
    r'[^>]*?content\s*=\s*["\']([^"\']*?)["\']',
    re.IGNORECASE | re.DOTALL,
)
_OG_RE_REV = re.compile(
    r'<meta\s[^>]*?'
    r'content\s*=\s*["\']([^"\']*?)["\']'
    r'[^>]*?(?:property|name)\s*=\s*["\']og:(\w+)["\']',
    re.IGNORECASE | re.DOTALL,
)
_TITLE_RE = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE)
_DESC_RE = re.compile(
    r'<meta\s[^>]*?name\s*=\s*["\']description["\'][^>]*?content\s*=\s*["\']([^"\']*?)["\']',
    re.IGNORECASE | re.DOTALL,
)


def _parse_og(html: str, url: str) -> dict:
    """Extract OG tags from HTML, with fallback to <title> and meta description."""
    og: dict[str, str] = {}

    for m in _OG_RE.finditer(html):
        og.setdefault(m.group(1).lower(), m.group(2))
    for m in _OG_RE_REV.finditer(html):
        og.setdefault(m.group(2).lower(), m.group(1))

    title = og.get("title", "")
    description = og.get("description", "")
    image = og.get("image", "")
    site_name = og.get("site_name", "")

    # Fallback: <title>
    if not title:
        m = _TITLE_RE.search(html)
        if m:
            title = m.group(1).strip()

    # Fallback: <meta name="description">
    if not description:
        m = _DESC_RE.search(html)
        if m:
            description = m.group(1).strip()

    # Resolve relative image URL
    if image and not image.startswith("http"):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        image = base + ("" if image.startswith("/") else "/") + image

    # Derive site_name from hostname if missing
    if not site_name:
        parsed = urlparse(url)
        site_name = parsed.netloc.removeprefix("www.")

    return {
        "title": title[:300],
        "description": description[:500],
        "image": image,
        "site_name": site_name,
        "url": url,
    }


# ── SSRF protection ───────────────────────────────────────────────────────

def _is_internal_host(host: str) -> bool:
    """Check if host resolves to internal/private IP (SSRF protection)."""
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
        return True
    try:
        ips = socket.getaddrinfo(host, None)
        for info in ips:
            addr = ipaddress.ip_address(info[4][0])
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return True
            # AWS metadata endpoint
            if str(addr).startswith("169.254."):
                return True
    except (socket.gaierror, ValueError):
        pass
    return False


# ── Endpoint ───────────────────────────────────────────────────────────────
@router.get("/link-preview")
async def link_preview(
    url: str = Query(..., min_length=8, max_length=2048),
    u: User = Depends(get_current_user),
):
    """Fetch Open Graph metadata for a URL."""
    # Validate URL scheme
    if not url.startswith(("http://", "https://")):
        return JSONResponse({"title": "", "description": "", "image": "", "site_name": "", "url": url})

    # Block private/internal IPs (SSRF protection)
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if _is_internal_host(host):
            return JSONResponse({"title": "", "description": "", "image": "", "site_name": "", "url": url})
    except Exception:
        return JSONResponse({"title": "", "description": "", "image": "", "site_name": "", "url": url})

    # Check cache
    cached = _cache_get(url)
    if cached is not None:
        return cached

    # Fetch
    try:
        async with _AsyncClient(
            follow_redirects=False,
            timeout=5.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml",
            },
        ) as client:
            resp = await client.get(url)

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            empty = {"title": "", "description": "", "image": "", "site_name": "", "url": url}
            _cache_set(url, empty)
            return empty

        # Limit parsing to first 50KB
        html = resp.text[:50_000]
        result = _parse_og(html, url)
        _cache_set(url, result)
        return result

    except Exception as e:
        logger.debug(f"Link preview fetch failed for {url}: {e}")
        empty = {"title": "", "description": "", "image": "", "site_name": "", "url": url}
        return empty
