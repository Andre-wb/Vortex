"""QR Code Login — desktop показывает QR, телефон подтверждает вход."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.authentication._helpers import (
    _allow_login_attempt,
    router,
)
from app.config import Config
from app.database import get_db
from app.models import User
from app.security import auth_state_backend as _auth_state
from app.security.auth_jwt import create_access_token, create_refresh_token
from app.security.crypto import derive_x25519_session_key, load_or_create_node_keypair
from app.security.ip_privacy import raw_ip_for_ratelimit, sanitize_ip

logger = logging.getLogger(__name__)

_QR_UNAVAILABLE = "QR sign-in is temporarily unavailable"


@router.post("/qr-init")
async def qr_init(request: Request, db: Session = Depends(get_db)):
    """Шаг 1 QR-входа — создаёт QR-сессию и возвращает SVG."""
    try:
        opened = _auth_state.qr_open()
    except RuntimeError as error:
        raise HTTPException(503, _QR_UNAVAILABLE) from error

    _, server_pub = load_or_create_node_keypair(Config.KEYS_DIR)

    import io

    import qrcode
    import qrcode.image.svg as qr_svg

    qr_data = (
        f"vortex://qr-login?s={opened.session_id}&c={opened.challenge_id}&p={server_pub.hex()}"
    )
    qr_obj = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=3)
    qr_obj.add_data(qr_data)
    qr_obj.make(fit=True)
    img = qr_obj.make_image(image_factory=qr_svg.SvgPathFillImage)
    buf = io.BytesIO()
    img.save(buf)
    svg_str = buf.getvalue().decode("utf-8")
    if svg_str.startswith("<?xml"):
        svg_str = svg_str[svg_str.index("?>") + 2 :].lstrip()

    return {
        "session_id": opened.session_id,
        "qr_svg": svg_str,
        "expires_in": opened.expires_in,
        "challenge": opened.challenge.hex(),
        "server_pubkey": server_pub.hex(),
    }


class QRConfirmRequest(BaseModel):
    session_id: str
    pubkey: str
    proof: str


@router.post("/qr-confirm")
async def qr_confirm(body: QRConfirmRequest, request: Request, db: Session = Depends(get_db)):
    """Шаг 2 QR-входа — телефон подтверждает вход через X25519 proof."""
    ip = raw_ip_for_ratelimit(request)
    if not _allow_login_attempt(ip):
        raise HTTPException(429, "Too many attempts")

    try:
        answer = _auth_state.qr_answer(body.session_id)
    except ValueError:
        raise HTTPException(401, "QR session not found or expired") from None
    except RuntimeError as error:
        raise HTTPException(503, _QR_UNAVAILABLE) from error

    if answer.outcome == "session_missing":
        raise HTTPException(401, "QR session not found or expired")
    if answer.outcome == "already_confirmed":
        raise HTTPException(409, "QR session already used")
    if answer.outcome == "challenge_missing":
        raise HTTPException(401, "Challenge expired")
    if not answer.ready:
        raise HTTPException(401, "QR session mismatch")

    user = (
        db.query(User)
        .filter(User.x25519_public_key == body.pubkey, User.is_active.is_(True))
        .first()
    )
    if not user:
        raise HTTPException(401, "User with this key not found")

    server_priv, _ = load_or_create_node_keypair(Config.KEYS_DIR)
    try:
        client_pub = bytes.fromhex(body.pubkey)
        shared = derive_x25519_session_key(server_priv, client_pub)
        if isinstance(shared, list):
            shared = bytes(shared)
    except Exception:
        raise HTTPException(401, "Key computation error") from None

    expected = hmac.new(shared, answer.challenge, hashlib.sha256).hexdigest()
    if not secrets.compare_digest(body.proof, expected):
        raise HTTPException(401, "Invalid proof")

    try:
        confirmation = _auth_state.qr_confirm(body.session_id, int(user.id))
    except RuntimeError as error:
        raise HTTPException(503, _QR_UNAVAILABLE) from error

    if confirmation == "missing":
        raise HTTPException(401, "QR session not found or expired")
    if confirmation == "already_confirmed":
        raise HTTPException(409, "QR session already used")

    logger.info(f"QR-login confirmed: user={user.username} session={body.session_id}")
    return {"ok": True}


@router.get("/qr-check/{session_id}")
async def qr_check(session_id: str, request: Request, db: Session = Depends(get_db)):
    """Polling с десктопа — ждёт подтверждения QR-сессии."""
    try:
        handover = _auth_state.qr_hand_over(session_id)
    except ValueError:
        raise HTTPException(404, "Session not found") from None
    except RuntimeError as error:
        raise HTTPException(503, _QR_UNAVAILABLE) from error

    if handover.outcome == "missing":
        raise HTTPException(404, "Session not found")
    if not handover.taken:
        return {"confirmed": False}

    user = db.query(User).filter(User.id == handover.user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(401, "User not found")

    access_token = create_access_token(user.id, user.phone, user.username)
    raw_refresh, _exp = create_refresh_token(
        user.id, db, sanitize_ip(request), request.headers.get("user-agent")
    )

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
    secure_cookie = Config.IS_PRODUCTION or request.url.scheme == "https"
    response = JSONResponse(content=data)
    response.set_cookie(
        "access_token", access_token, httponly=True, secure=secure_cookie, samesite="Lax", max_age=3600
    )
    response.set_cookie(
        "refresh_token", raw_refresh, httponly=True, secure=secure_cookie, samesite="Lax", max_age=86400 * 30
    )
    return response
