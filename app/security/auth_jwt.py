"""
JWT authentication — HMAC-HS256 with a local secret.
X25519 is used for E2E encryption between devices, not for JWT.
No RSA, no external CAs.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.models import RefreshToken, User
from app.security import auth_state_backend as _auth_state
from app.security.crypto import hash_token

logger = logging.getLogger(__name__)

_JWT_ALG = "HS256"


def revoke_access_token(token: str) -> None:
    """Add an access token's jti to the denylist until it would expire."""
    try:
        payload = jwt.decode(
            token,
            Config.JWT_SECRET,
            algorithms=[_JWT_ALG],
            options={"verify_exp": False, "verify_aud": False},
        )
    except jwt.InvalidTokenError:
        return
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return
    try:
        _auth_state.revoke_access(str(jti), float(exp))
    except ValueError:
        logger.warning("JWT denylist: отказ по идентификатору токена")
    except RuntimeError as error:
        raise HTTPException(503, "Token revocation is temporarily unavailable") from error


def _is_jti_revoked(jti: str) -> bool:
    if not jti:
        return False
    return _auth_state.access_revoked(str(jti))


# Access Token (JWT HS256)


def create_access_token(user_id: int, phone: str, username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MIN)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "phone": phone,
        "username": username,
        "iat": now,
        "exp": exp,
        "jti": secrets.token_hex(16),
        "typ": "access",
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=_JWT_ALG)


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            Config.JWT_SECRET,
            algorithms=[_JWT_ALG],
            options={"verify_aud": False, "require": ["sub", "exp", "jti"]},
            leeway=30,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired") from None
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {e}") from None
    # FIX F4: only true access tokens may authenticate a session. Other tokens
    # signed with the same secret (e.g. mini-app typ="miniapp") must NOT be
    # accepted as a full access token. create_access_token sets typ="access",
    # so legitimate access tokens are unaffected. This covers get_current_user
    # and get_user_ws (both route through here).
    if payload.get("typ") != "access":
        raise HTTPException(401, "Invalid token type")
    if _is_jti_revoked(payload.get("jti", "")):
        raise HTTPException(401, "Token revoked")
    return payload


# Refresh Token (opaque, SHA-256 hash stored in DB via Rust)


def create_refresh_token(
    user_id: int,
    db: Session,
    ip: str | None = None,
    ua: str | None = None,
) -> tuple[str, datetime]:
    # Clean up expired tokens
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.expires_at < datetime.now(timezone.utc),
    ).delete()

    raw = secrets.token_urlsafe(64)
    exp = datetime.now(timezone.utc) + timedelta(days=Config.REFRESH_TOKEN_EXPIRE_DAYS)

    # hash_token -> SHA-256 via Rust (constant-time)
    db.add(
        RefreshToken(
            user_id=user_id,
            token_hash=hash_token(raw),
            expires_at=exp,
            ip_address=ip,
            user_agent=ua,
        )
    )
    db.commit()
    return raw, exp


def verify_refresh_token(raw: str, db: Session) -> User:
    token_hash = hash_token(raw)
    rec = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
        .first()
    )
    if not rec:
        raise HTTPException(401, "Refresh token is invalid or expired")
    user = db.query(User).filter(User.id == rec.user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(401, "User not found")
    rec.revoked_at = datetime.now(timezone.utc)
    try:
        db.commit()
    except Exception:
        db.rollback()
    return user


# FastAPI Dependencies


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(401, "Unauthorized")
    payload = decode_access_token(token)
    user = (
        db.query(User)
        .filter(
            User.id == int(payload["sub"]),
            User.is_active.is_(True),
        )
        .first()
    )
    if not user:
        raise HTTPException(401, "User not found")
    return user


async def get_user_ws(token: str, db: Session) -> User:
    """For WebSocket — token is passed as a query parameter."""
    payload = decode_access_token(token)
    user = (
        db.query(User)
        .filter(
            User.id == int(payload["sub"]),
            User.is_active.is_(True),
        )
        .first()
    )
    if not user:
        raise HTTPException(401, "User not found")
    return user
