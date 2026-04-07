"""Общие хелперы, роутер и in-memory хранилища для аутентификации."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from sqlalchemy.orm import Session

from app.config import Config
from app.models import User, UserDevice
from app.security.auth_jwt import create_access_token, create_refresh_token
from app.security.crypto import hash_password as _hp, verify_password
from app.security.ip_privacy import sanitize_ip

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/authentication", tags=["authentication"])

# ── Rate limiting ─────────────────────────────────────────────────────────
_auth_rate: dict[str, list[float]] = {}
_AUTH_RATE_WINDOW = 60
_AUTH_RATE_LOGIN = 10
_AUTH_RATE_REGISTER = 5
_IS_TESTING = os.getenv("TESTING", "").lower() == "true"


def _check_auth_rate(ip: str, limit: int) -> bool:
    """Return True if request is within rate limit, False if exceeded."""
    if _IS_TESTING:
        return True
    now = time.monotonic()
    timestamps = _auth_rate.get(ip, [])
    timestamps = [t for t in timestamps if now - t < _AUTH_RATE_WINDOW]
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    _auth_rate[ip] = timestamps
    return True


# ── Dummy hash для timing-attack prevention ───────────────────────────────
try:
    _DUMMY_HASH = _hp("__dummy_timing_password__")
except Exception:
    _DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dummyhashvalue"


# ── In-memory хранилище challenge'ов (X25519 + QR) ───────────────────────
@dataclass
class _Challenge:
    """Одноразовый challenge для X25519 аутентификации."""
    challenge:  bytes
    user_id:    int
    pubkey_hex: str
    expires_at: float

_challenges: dict[str, _Challenge] = {}
_challenges_lock = threading.Lock()
_CHALLENGE_TTL = 60


def _cleanup_expired_challenges() -> None:
    now = time.monotonic()
    with _challenges_lock:
        expired = [cid for cid, ch in _challenges.items() if now > ch.expires_at]
        for cid in expired:
            del _challenges[cid]


# ── Парсинг User-Agent ────────────────────────────────────────────────────
def _parse_device_name(ua: str | None) -> tuple[str, str]:
    """Parse User-Agent into (device_name, device_type)."""
    if not ua:
        return "Unknown device", "web"
    ua_lower = ua.lower()

    browser = "Browser"
    if "firefox" in ua_lower:
        browser = "Firefox"
    elif "edg" in ua_lower:
        browser = "Edge"
    elif "chrome" in ua_lower and "safari" in ua_lower:
        browser = "Chrome"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "opera" in ua_lower or "opr/" in ua_lower:
        browser = "Opera"

    os_name = ""
    if "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "mac" in ua_lower:
        os_name = "macOS"
    elif "windows" in ua_lower:
        os_name = "Windows"
    elif "linux" in ua_lower:
        os_name = "Linux"

    device_type = "web"
    if "mobile" in ua_lower or "iphone" in ua_lower or "android" in ua_lower:
        device_type = "mobile"
    elif "electron" in ua_lower or "tauri" in ua_lower:
        device_type = "desktop"

    name = f"{browser} on {os_name}" if os_name else browser
    return name, device_type


# ── Установка auth cookies ────────────────────────────────────────────────
def _set_auth_cookies(response: Response, user: User, db: Session, request: Request) -> None:
    """Устанавливает access_token и refresh_token как HttpOnly cookies."""
    from app.security.crypto import hash_token

    ip = sanitize_ip(request)
    ua = request.headers.get("user-agent")
    access_token = create_access_token(user.id, user.phone, user.username)
    raw_refresh, _exp = create_refresh_token(user.id, db, ip, ua)

    device_name, device_type = _parse_device_name(ua)
    device = UserDevice(
        user_id=user.id,
        device_name=device_name,
        device_type=device_type,
        ip_address=ip,
        refresh_token_hash=hash_token(raw_refresh),
    )
    db.add(device)
    db.commit()

    for name, val, max_age in [
        ("access_token",  access_token, 3600),
        ("refresh_token", raw_refresh,  86400 * 30),
    ]:
        response.set_cookie(
            name, val,
            httponly=True,
            secure=Config.IS_PRODUCTION,
            samesite="Lax",
            max_age=max_age,
            path="/",
        )
