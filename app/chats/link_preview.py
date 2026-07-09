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
import time
from collections import OrderedDict, defaultdict
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request

# Separate reference so tests can patch this without affecting httpx globally
_AsyncClient = httpx.AsyncClient
from fastapi.responses import JSONResponse

from app.models import User
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["link-preview"])

# FIX F12(1): /api/link-preview is an authenticated outbound-fetch SSRF surface.
# Throttle it per-user AND per-IP (mirrors the limiter pattern in
# app/chats/translate.py) so a single account/host cannot drive unbounded
# server-side requests. /api/link-preview is also re-included in the WAF
# (EXCLUDED_PATHS removal, FIX F12-3) so the WAF per-IP cap applies on top.
_RATE_LIMIT = 30
_RATE_WINDOW = 60  # 30 previews / minute per identity

_user_hits: dict[int, list[float]] = defaultdict(list)
_ip_hits: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(bucket: dict, key, label: str) -> None:
    now = time.time()
    cutoff = now - _RATE_WINDOW
    bucket[key] = [t for t in bucket[key] if t > cutoff]
    if len(bucket[key]) >= _RATE_LIMIT:
        raise HTTPException(429, f"Link-preview rate limit exceeded ({_RATE_LIMIT}/min per {label})")
    bucket[key].append(now)

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



def _ip_is_blocked(addr: ipaddress._BaseAddress) -> bool:
    """True if an IP belongs to a private/reserved/link-local range we must not reach."""
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return True
    # AWS / cloud metadata endpoint (link-local already covers 169.254/16, but be explicit)
    if str(addr).startswith("169.254."):
        return True
    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — unwrap and re-check
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None and _ip_is_blocked(mapped):
        return True
    return False


def _is_internal_host(host: str) -> bool:
    """Check if host resolves to internal/private IP (SSRF protection)."""
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
        return True
    try:
        ips = socket.getaddrinfo(host, None)
        for info in ips:
            addr = ipaddress.ip_address(info[4][0])
            if _ip_is_blocked(addr):
                return True
    except (socket.gaierror, ValueError):
        pass
    return False


def _resolve_and_pin(host: str) -> tuple[str, Optional[str]]:
    """
    FIX F12(2): close the DNS-rebinding TOCTOU. Resolve the host EXACTLY ONCE and
    validate EVERY returned A/AAAA record against the private/reserved/link-local
    blocklist.

    Returns (verdict, ip):
      ("ok", "<safe-ip>")  — every record resolved to a public IP; pin to this one.
      ("blocked", None)    — at least one record is internal, or an obviously
                             internal literal host → caller MUST refuse to fetch.
      ("unresolved", None) — DNS yielded nothing (NXDOMAIN, etc.). No IP exists to
                             rebind toward at our layer; caller may proceed without
                             pinning (follow_redirects stays off as defence-in-depth).
    """
    if host in ("localhost", "0.0.0.0", "metadata.google.internal"):
        return ("blocked", None)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, ValueError, UnicodeError):
        return ("unresolved", None)

    chosen: Optional[str] = None
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return ("blocked", None)  # unparseable → refuse rather than risk it
        if _ip_is_blocked(addr):
            return ("blocked", None)  # ANY internal record → refuse (rebinding-safe)
        if chosen is None:
            chosen = str(addr)
    if chosen is None:
        return ("unresolved", None)
    return ("ok", chosen)


def _build_pinned_transport(pinned_ip: str) -> httpx.AsyncHTTPTransport:
    """
    Build an httpx transport that forces every TCP connect to a pre-validated IP
    while preserving the original hostname for TLS SNI / certificate validation.
    Implements FIX F12(2): the IP validated in _resolve_and_pin is the exact IP
    we connect to — httpcore never performs a second DNS lookup that an attacker
    could rebind. We wrap (by composition) the pool's real network backend and
    rewrite only the connect target.
    """
    transport = httpx.AsyncHTTPTransport()
    inner = transport._pool._network_backend

    class _PinningBackend:
        # Delegate everything to the real backend, but pin connect_tcp's host.
        async def connect_tcp(self, host, port, timeout=None,
                              local_address=None, socket_options=None):
            return await inner.connect_tcp(
                pinned_ip, port, timeout=timeout,
                local_address=local_address, socket_options=socket_options,
            )

        async def connect_unix_socket(self, *a, **kw):
            return await inner.connect_unix_socket(*a, **kw)

        async def sleep(self, seconds):
            return await inner.sleep(seconds)

    transport._pool._network_backend = _PinningBackend()
    return transport


@router.get("/link-preview")
async def link_preview(
    request: Request,
    url: str = Query(..., min_length=8, max_length=2048),
    u: User = Depends(get_current_user),
):
    """Fetch Open Graph metadata for a URL."""
    # FIX F12(1): per-user AND per-IP throttle before any outbound work.
    _check_rate_limit(_user_hits, u.id, "user")
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(_ip_hits, client_ip, "ip")

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

    # FIX F12(2): resolve ONCE, validate every record, and pin the connection to
    # that exact IP so httpx cannot re-resolve to an internal address at connect
    # time (DNS-rebinding TOCTOU). A "blocked" verdict refuses the fetch outright.
    verdict, pinned_ip = _resolve_and_pin(host)
    if verdict == "blocked":
        return JSONResponse({"title": "", "description": "", "image": "", "site_name": "", "url": url})

    # Build client kwargs; pin the validated IP at the socket layer when we have one.
    _client_kwargs = dict(
        follow_redirects=False,
        timeout=5.0,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    if pinned_ip is not None:
        _client_kwargs["transport"] = _build_pinned_transport(pinned_ip)

    # Fetch
    try:
        async with _AsyncClient(**_client_kwargs) as client:
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
