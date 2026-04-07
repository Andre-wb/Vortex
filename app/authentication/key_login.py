"""X25519 Challenge-Response — беспарольный вход."""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.security.ip_privacy import raw_ip_for_ratelimit
from app.models import KeyLoginRequest, User
from app.security.crypto import derive_x25519_session_key, load_or_create_node_keypair

from app.authentication._helpers import (
    _AUTH_RATE_LOGIN, _CHALLENGE_TTL, _Challenge,
    _challenges, _challenges_lock, _check_auth_rate,
    _cleanup_expired_challenges, _set_auth_cookies, router,
)
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@router.get("/challenge")
async def get_challenge(identifier: str, db: Session = Depends(get_db)):
    """Шаг 1 беспарольного X25519 входа — challenge + публичный ключ сервера."""
    _cleanup_expired_challenges()

    user = (
        db.query(User).filter(User.phone == identifier).first()
        or db.query(User).filter(User.username == identifier.lower()).first()
    )

    if not user or not user.x25519_public_key:
        return {
            "challenge_id": secrets.token_hex(16),
            "challenge": secrets.token_hex(32),
            "server_pubkey": "0" * 64,
            "expires_in": _CHALLENGE_TTL,
        }

    _, server_pub = load_or_create_node_keypair(Config.KEYS_DIR)
    challenge_bytes = secrets.token_bytes(32)
    challenge_id = secrets.token_hex(16)

    with _challenges_lock:
        _challenges[challenge_id] = _Challenge(
            challenge=challenge_bytes,
            user_id=user.id,
            pubkey_hex=user.x25519_public_key,
            expires_at=time.monotonic() + _CHALLENGE_TTL,
        )

    return {
        "challenge_id": challenge_id,
        "challenge": challenge_bytes.hex(),
        "server_pubkey": server_pub.hex(),
        "expires_in": _CHALLENGE_TTL,
    }


@router.post("/login-key")
async def login_with_key(body: KeyLoginRequest, request: Request,
                         db: Session = Depends(get_db)):
    """Шаг 2 беспарольного X25519 входа — проверка HMAC proof."""
    ip = raw_ip_for_ratelimit(request)
    if not _check_auth_rate(ip, _AUTH_RATE_LOGIN):
        raise HTTPException(429, "Слишком много попыток входа. Подождите минуту.")

    with _challenges_lock:
        ch = _challenges.pop(body.challenge_id, None)

    if not ch:
        raise HTTPException(401, "Challenge не найден или уже использован")
    if time.monotonic() > ch.expires_at:
        raise HTTPException(401, "Challenge истёк (60 секунд)")
    if not secrets.compare_digest(ch.pubkey_hex, body.pubkey):
        raise HTTPException(401, "Публичный ключ не совпадает с зарегистрированным")

    server_priv, _ = load_or_create_node_keypair(Config.KEYS_DIR)
    client_pub = bytes.fromhex(body.pubkey)

    try:
        shared = derive_x25519_session_key(server_priv, client_pub)
        if isinstance(shared, list):
            shared = bytes(shared)
    except Exception as e:
        logger.warning(f"Key derivation failed: {e}")
        raise HTTPException(401, "Ошибка вычисления общего секрета")

    expected_proof = hmac.new(shared, ch.challenge, hashlib.sha256).hexdigest()

    if not secrets.compare_digest(body.proof, expected_proof):
        raise HTTPException(401, "Неверный proof — возможно неверный приватный ключ")

    user = db.query(User).filter(
        User.id == ch.user_id, User.is_active == True
    ).first()
    if not user:
        raise HTTPException(401, "Пользователь не найден или деактивирован")

    user.last_seen = datetime.now(timezone.utc)
    db.commit()
    logger.info(f"Key-login: {user.username}")

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
