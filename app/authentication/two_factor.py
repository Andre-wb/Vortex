"""2FA (TOTP) — настройка, включение, отключение, верификация при логине."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import TwoFALoginRequest, TwoFAVerifyRequest, User
from app.security.auth_jwt import get_current_user

from app.security.ip_privacy import sanitize_ip

from app.authentication._helpers import _set_auth_cookies, router

# ── Per-user TOTP rate limiter (in-memory) ────────────────────────────────
_totp_attempts: dict[int, list] = {}  # user_id -> [timestamps]
_TOTP_MAX_ATTEMPTS = 5
_TOTP_WINDOW = 300  # 5 minutes


def _check_totp_rate(user_id: int) -> bool:
    """Return True if the user is allowed to attempt TOTP, False if rate-limited."""
    now = time.monotonic()
    attempts = _totp_attempts.get(user_id, [])
    # Remove expired attempts
    attempts = [t for t in attempts if now - t < _TOTP_WINDOW]
    _totp_attempts[user_id] = attempts
    if len(attempts) >= _TOTP_MAX_ATTEMPTS:
        return False
    attempts.append(now)
    return True


@router.post("/2fa/setup")
async def setup_2fa(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Генерирует TOTP-секрет и возвращает URI для QR-кода."""
    import pyotp
    secret = pyotp.random_base32()
    u.totp_secret = secret
    db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=u.username, issuer_name="Vortex")
    return {"secret": secret, "uri": uri}


@router.post("/2fa/enable")
async def enable_2fa(body: TwoFAVerifyRequest, u: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """Проверяет TOTP-код и включает 2FA."""
    import pyotp
    if not u.totp_secret:
        raise HTTPException(400, "Сначала настройте 2FA через /2fa/setup")
    totp = pyotp.TOTP(u.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(401, "Неверный код")
    u.totp_enabled = True
    db.commit()
    return {"ok": True}


@router.post("/2fa/disable")
async def disable_2fa(body: TwoFAVerifyRequest, u: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """Отключает 2FA после подтверждения TOTP-кодом."""
    import pyotp
    if not u.totp_enabled:
        return {"ok": True}
    totp = pyotp.TOTP(u.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(401, "Неверный код")
    u.totp_enabled = False
    u.totp_secret = None
    db.commit()
    return {"ok": True}


@router.post("/2fa/verify-login")
async def verify_2fa_login(body: TwoFALoginRequest, request: Request,
                           db: Session = Depends(get_db)):
    """Подтверждение 2FA-кода при логине."""
    import pyotp
    user = db.query(User).filter(User.id == body.user_id, User.is_active == True).first()
    if not user or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(401, "Пользователь не найден или 2FA не включена")

    # Rate limit: max 5 attempts per 5 minutes per user
    if not _check_totp_rate(user.id):
        raise HTTPException(429, "Too many attempts, try again later")

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(401, "Неверный код 2FA")

    user.last_seen = datetime.now(timezone.utc)
    user.last_ip = sanitize_ip(request)
    db.commit()

    data = {
        "ok": True,
        "user_id": user.id,
        "username": user.username,
        "phone": user.phone,
        "display_name": user.display_name or user.username,
        "avatar_emoji": user.avatar_emoji,
        "avatar_url": user.avatar_url,
        "email": user.email,
        "x25519_public_key": user.x25519_public_key,
        "network_mode": user.network_mode or "local",
        "custom_status": user.custom_status,
        "status_emoji": user.status_emoji,
        "presence": user.presence or "online",
        "created_at": user.created_at.isoformat() if user.created_at else "",
    }
    response = JSONResponse(content=data)
    _set_auth_cookies(response, user, db, request)
    return response


@router.get("/2fa/status")
async def get_2fa_status(u: User = Depends(get_current_user)):
    """Возвращает статус 2FA для текущего пользователя."""
    return {"enabled": bool(u.totp_enabled)}
