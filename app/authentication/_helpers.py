"""Общие хелперы, роутер и in-memory хранилища для аутентификации."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from sqlalchemy.orm import Session

from app.config import Config
from app.models import User, UserDevice
from app.security import auth_state_backend as _auth_state
from app.security.auth_jwt import create_access_token, create_refresh_token
from app.security.crypto import hash_password as _hp
from app.security.ip_privacy import sanitize_ip

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/authentication", tags=["authentication"])

_IS_TESTING = os.getenv("TESTING", "").lower() == "true"


def _allow_login_attempt(ip: str) -> bool:
    """True, если попытка входа с этого адреса укладывается в общий предел."""
    if _IS_TESTING:
        return True
    return _auth_state.entry_login_allowed(ip)


def _allow_registration_attempt(ip: str) -> bool:
    """True, если попытка регистрации с этого адреса укладывается в общий предел."""
    if _IS_TESTING:
        return True
    return _auth_state.entry_register_allowed(ip)


try:
    _DUMMY_HASH = _hp("__dummy_timing_password__")
except Exception:
    _DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dummyhashvalue"


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


def _set_auth_cookies(response: Response, user: User, db: Session, request: Request) -> None:
    """Устанавливает access_token и refresh_token как HttpOnly cookies."""
    from app.security.crypto import hash_token

    ip = sanitize_ip(request)
    ua = request.headers.get("user-agent")
    access_token = create_access_token(user.id, user.phone, user.username)
    raw_refresh, _exp = create_refresh_token(user.id, db, ip, ua)

    device_name, device_type = _parse_device_name(ua)

    # Дедуп UserDevice по стабильному client_device_id (заголовок
    # X-Device-Id) — переиспользуем строку физического устройства вместо новой
    # на каждый логин. Обновление refresh_token_hash консистентно с refresh-флоу
    # (session.py тоже переиспользует и обновляет строку). Без заголовка
    # (старый клиент) — прежнее поведение: новая строка.
    client_device_id = request.headers.get("x-device-id")
    if client_device_id and not (
        len(client_device_id) == 32 and all(c in "0123456789abcdef" for c in client_device_id)
    ):
        client_device_id = None  # игнорируем мусорный заголовок

    device = None
    if client_device_id:
        device = (
            db.query(UserDevice)
            .filter(
                UserDevice.user_id == user.id,
                UserDevice.client_device_id == client_device_id,
            )
            .first()
        )

    if device is not None:
        device.refresh_token_hash = hash_token(raw_refresh)
        device.ip_address = ip
        device.device_name = device_name
        device.device_type = device_type
        device.last_active = datetime.now(timezone.utc)
    else:
        device = UserDevice(
            user_id=user.id,
            device_name=device_name,
            device_type=device_type,
            ip_address=ip,
            refresh_token_hash=hash_token(raw_refresh),
            client_device_id=client_device_id,
        )
        db.add(device)
    db.commit()

    # Enforce session limit — only if user explicitly set one (0 = unlimited)
    # Session limit is stored in localStorage on client, not on server by default

    # mark auth cookies Secure whenever the connection is HTTPS, not only
    # in production, so tokens are never sent over plaintext on TLS deployments
    # that are not flagged as production.
    secure_cookie = Config.IS_PRODUCTION or request.url.scheme == "https"

    for name, val, max_age in [
        ("access_token", access_token, 3600),
        ("refresh_token", raw_refresh, 86400 * 30),
    ]:
        response.set_cookie(
            name,
            val,
            httponly=True,
            secure=secure_cookie,
            samesite="Lax",
            max_age=max_age,
            path="/",
        )
