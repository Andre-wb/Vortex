"""QR Code Login — desktop показывает QR, телефон подтверждает вход."""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.models import User
from app.security.auth_jwt import create_access_token, create_refresh_token
from app.security.crypto import derive_x25519_session_key, load_or_create_node_keypair

from app.security.ip_privacy import raw_ip_for_ratelimit, sanitize_ip

from app.authentication._helpers import (
    _AUTH_RATE_LOGIN, _Challenge, _challenges, _challenges_lock,
    _check_auth_rate, router,
)

logger = logging.getLogger(__name__)

# ── QR Session Storage ────────────────────────────────────────────────────

@dataclass
class _QRSession:
    session_id:    str
    challenge_id:  str
    expires_at:    float
    confirmed:     bool = False
    user_id:       int = 0
    access_token:  str = ""
    refresh_token: str = ""

_qr_sessions: dict[str, _QRSession] = {}
_qr_lock = threading.Lock()
_QR_TTL = 300


def _cleanup_qr_sessions() -> None:
    now = time.monotonic()
    with _qr_lock:
        expired = [sid for sid, s in _qr_sessions.items() if now > s.expires_at]
        for sid in expired:
            _qr_sessions.pop(sid, None)


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.post("/qr-init")
async def qr_init(request: Request, db: Session = Depends(get_db)):
    """Шаг 1 QR-входа — создаёт QR-сессию и возвращает SVG."""
    _cleanup_qr_sessions()

    session_id = secrets.token_hex(24)
    challenge_id = secrets.token_hex(16)
    challenge_bytes = secrets.token_bytes(32)

    _, server_pub = load_or_create_node_keypair(Config.KEYS_DIR)

    with _challenges_lock:
        _challenges[challenge_id] = _Challenge(
            challenge=challenge_bytes,
            user_id=0,
            pubkey_hex=f"QR:{session_id}",
            expires_at=time.monotonic() + _QR_TTL,
        )

    with _qr_lock:
        _qr_sessions[session_id] = _QRSession(
            session_id=session_id,
            challenge_id=challenge_id,
            expires_at=time.monotonic() + _QR_TTL,
        )

    import qrcode
    import qrcode.image.svg as qr_svg
    import io
    qr_data = f"vortex://qr-login?s={session_id}&c={challenge_id}&p={server_pub.hex()}"
    qr_obj = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=3)
    qr_obj.add_data(qr_data)
    qr_obj.make(fit=True)
    img = qr_obj.make_image(image_factory=qr_svg.SvgPathFillImage)
    buf = io.BytesIO()
    img.save(buf)
    svg_str = buf.getvalue().decode("utf-8")
    if svg_str.startswith("<?xml"):
        svg_str = svg_str[svg_str.index("?>") + 2:].lstrip()

    return {
        "session_id": session_id,
        "qr_svg": svg_str,
        "expires_in": _QR_TTL,
        "challenge": challenge_bytes.hex(),
        "server_pubkey": server_pub.hex(),
    }


class QRConfirmRequest(BaseModel):
    session_id: str
    pubkey:     str
    proof:      str


@router.post("/qr-confirm")
async def qr_confirm(body: QRConfirmRequest, request: Request, db: Session = Depends(get_db)):
    """Шаг 2 QR-входа — телефон подтверждает вход через X25519 proof."""
    ip = raw_ip_for_ratelimit(request)
    if not _check_auth_rate(ip, _AUTH_RATE_LOGIN):
        raise HTTPException(429, "Слишком много попыток")

    with _qr_lock:
        qs = _qr_sessions.get(body.session_id)
    if not qs or time.monotonic() > qs.expires_at:
        raise HTTPException(401, "QR-сессия не найдена или истекла")
    if qs.confirmed:
        raise HTTPException(409, "QR-сессия уже использована")

    with _challenges_lock:
        ch = _challenges.pop(qs.challenge_id, None)
    if not ch or time.monotonic() > ch.expires_at:
        raise HTTPException(401, "Challenge истёк")

    if ch.pubkey_hex != f"QR:{body.session_id}":
        raise HTTPException(401, "Несоответствие QR-сессии")

    user = db.query(User).filter(User.x25519_public_key == body.pubkey, User.is_active == True).first()
    if not user:
        raise HTTPException(401, "Пользователь с таким ключом не найден")

    server_priv, _ = load_or_create_node_keypair(Config.KEYS_DIR)
    try:
        client_pub = bytes.fromhex(body.pubkey)
        shared = derive_x25519_session_key(server_priv, client_pub)
        if isinstance(shared, list):
            shared = bytes(shared)
    except Exception:
        raise HTTPException(401, "Ошибка вычисления ключа")

    expected = hmac.new(shared, ch.challenge, hashlib.sha256).hexdigest()
    if not secrets.compare_digest(body.proof, expected):
        raise HTTPException(401, "Неверный proof")

    access_token = create_access_token(user.id, user.phone, user.username)
    raw_refresh, _exp = create_refresh_token(user.id, db,
                                              sanitize_ip(request),
                                              request.headers.get("user-agent"))

    with _qr_lock:
        qs.confirmed = True
        qs.user_id = user.id
        qs.access_token = access_token
        qs.refresh_token = raw_refresh

    logger.info(f"QR-login confirmed: user={user.username} session={body.session_id}")
    return {"ok": True}


@router.get("/qr-check/{session_id}")
async def qr_check(session_id: str, request: Request, db: Session = Depends(get_db)):
    """Polling с десктопа — ждёт подтверждения QR-сессии."""
    with _qr_lock:
        qs = _qr_sessions.get(session_id)
    if not qs:
        raise HTTPException(404, "Сессия не найдена")
    if time.monotonic() > qs.expires_at:
        with _qr_lock:
            _qr_sessions.pop(session_id, None)
        raise HTTPException(401, "QR-сессия истекла")

    if not qs.confirmed:
        return {"confirmed": False}

    user = db.query(User).filter(User.id == qs.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(401, "Пользователь не найден")

    with _qr_lock:
        _qr_sessions.pop(session_id, None)

    data = {
        "confirmed": True,
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
    response.set_cookie("access_token",  qs.access_token,  httponly=True, secure=Config.IS_PRODUCTION, samesite="Lax", max_age=3600)
    response.set_cookie("refresh_token", qs.refresh_token, httponly=True, secure=Config.IS_PRODUCTION, samesite="Lax", max_age=86400 * 30)
    return response
