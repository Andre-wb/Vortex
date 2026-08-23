"""X25519 Challenge-Response — беспарольный вход."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.authentication._helpers import (
    _allow_login_attempt,
    _set_auth_cookies,
    router,
)
from app.config import Config
from app.database import get_db
from app.models import KeyLoginRequest, User
from app.security import auth_state_backend as _auth_state
from app.security.crypto import derive_x25519_session_key, load_or_create_node_keypair
from app.security.ip_privacy import raw_ip_for_ratelimit

logger = logging.getLogger(__name__)

_LOGIN_UNAVAILABLE = "Key sign-in is temporarily unavailable"


@router.get("/challenge")
async def get_challenge(identifier: str, db: Session = Depends(get_db)):
    """Шаг 1 беспарольного X25519 входа — challenge + публичный ключ сервера."""
    user = (
        db.query(User).filter(User.phone == identifier).first()
        or db.query(User).filter(User.username == identifier.lower()).first()
    )

    _, server_pub = load_or_create_node_keypair(Config.KEYS_DIR)

    try:
        issued = None
        if user and user.x25519_public_key:
            try:
                issued = _auth_state.login_issue(int(user.id), user.x25519_public_key)
            except ValueError:
                logger.warning("Key-login: непригодный ключ у учётной записи %s", user.id)
        if issued is None:
            issued = _auth_state.login_issue_decoy()
    except RuntimeError as error:
        raise HTTPException(503, _LOGIN_UNAVAILABLE) from error

    return {
        "challenge_id": issued.challenge_id,
        "challenge": issued.challenge.hex(),
        "server_pubkey": server_pub.hex(),
        "expires_in": issued.expires_in,
    }


@router.post("/login-key")
async def login_with_key(body: KeyLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Шаг 2 беспарольного X25519 входа — проверка HMAC proof."""
    ip = raw_ip_for_ratelimit(request)
    if not _allow_login_attempt(ip):
        raise HTTPException(429, "Too many login attempts. Please wait a minute.")

    try:
        claim = _auth_state.login_claim(body.challenge_id, body.pubkey)
    except ValueError:
        raise HTTPException(401, "Challenge not found or already used") from None
    except RuntimeError as error:
        raise HTTPException(503, _LOGIN_UNAVAILABLE) from error

    if claim.outcome == "missing":
        raise HTTPException(401, "Challenge not found or already used")
    if not claim.taken:
        raise HTTPException(401, "Public key does not match the registered one")

    server_priv, _ = load_or_create_node_keypair(Config.KEYS_DIR)
    client_pub = bytes.fromhex(body.pubkey)

    try:
        shared = derive_x25519_session_key(server_priv, client_pub)
        if isinstance(shared, list):
            shared = bytes(shared)
    except Exception as e:
        logger.warning(f"Key derivation failed: {e}")
        raise HTTPException(401, "Shared secret computation error") from None

    expected_proof = hmac.new(shared, claim.challenge, hashlib.sha256).hexdigest()

    if not secrets.compare_digest(body.proof, expected_proof):
        raise HTTPException(401, "Invalid proof — possibly wrong private key")

    user = db.query(User).filter(User.id == claim.user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(401, "User not found or deactivated")

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
