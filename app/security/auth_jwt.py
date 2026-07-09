"""
JWT authentication — HMAC-HS256 with a local secret.
X25519 is used for E2E encryption between devices, not for JWT.
No RSA, no external CAs.
"""
from __future__ import annotations

import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import Config
from app.security.crypto import hash_token, verify_token_hash
from app.database import get_db
from app.models import RefreshToken, User

logger = logging.getLogger(__name__)

_JWT_ALG = "HS256"


# Access tokens are stateless and otherwise valid until `exp`. To make logout
# actually terminate an active/stolen access token, we keep a denylist of
# revoked `jti`s until their natural expiry.
#
# Storage backend:
#   - If Config.REDIS_URL is set → Redis (shared across all workers/hosts).
#     Each revoked jti is `SETEX jwt:revoked:<jti> <ttl> 1`, so it auto-expires
#     exactly when the token would have, and every process sees it.
#   - Otherwise → an in-process dict (single-process deployments only).
# If Redis is configured but unreachable, we fail safe: revocation also lands
# in the in-process set for the current worker, and reads fall back to it.
_JTI_PREFIX = "jwt:revoked:"

_revoked_jti: dict[str, float] = {}      # in-memory fallback
_revoked_lock = threading.Lock()

_redis_client = None
_redis_init_done = False
_redis_lock = threading.Lock()


def _get_redis():
    """Lazily create a shared Redis client, or None if not configured/available."""
    global _redis_client, _redis_init_done
    if _redis_init_done:
        return _redis_client
    with _redis_lock:
        if _redis_init_done:
            return _redis_client
        url = getattr(Config, "REDIS_URL", "") or ""
        if url:
            try:
                import redis
                client = redis.Redis.from_url(
                    url, decode_responses=True,
                    socket_connect_timeout=2, socket_timeout=2,
                )
                client.ping()
                _redis_client = client
                logger.info("JWT revocation denylist: using Redis backend")
            except Exception as e:
                logger.warning("JWT denylist: Redis unavailable (%s) — "
                               "falling back to in-process store", e)
                _redis_client = None
        _redis_init_done = True
    return _redis_client


def _purge_expired_jti(now_epoch: float) -> None:
    for j, exp in list(_revoked_jti.items()):
        if exp <= now_epoch:
            _revoked_jti.pop(j, None)


def revoke_access_token(token: str) -> None:
    """Add an access token's jti to the denylist until it would expire."""
    try:
        payload = jwt.decode(
            token, Config.JWT_SECRET, algorithms=[_JWT_ALG],
            options={"verify_exp": False, "verify_aud": False},
        )
    except jwt.InvalidTokenError:
        return
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return
    now = datetime.now(timezone.utc).timestamp()
    ttl = int(float(exp) - now)
    if ttl <= 0:
        return  # already expired — nothing to revoke

    r = _get_redis()
    if r is not None:
        try:
            r.setex(_JTI_PREFIX + jti, ttl, "1")
            return
        except Exception as e:
            logger.warning("JWT denylist: Redis SETEX failed (%s) — using local store", e)

    with _revoked_lock:
        _purge_expired_jti(now)
        _revoked_jti[jti] = float(exp)


def _is_jti_revoked(jti: str) -> bool:
    if not jti:
        return False
    r = _get_redis()
    if r is not None:
        try:
            if r.exists(_JTI_PREFIX + jti):
                return True
            # Fall through to also check the local store (covers tokens revoked
            # while Redis was briefly down on this worker).
        except Exception as e:
            logger.warning("JWT denylist: Redis EXISTS failed (%s) — using local store", e)

    now = datetime.now(timezone.utc).timestamp()
    with _revoked_lock:
        exp = _revoked_jti.get(jti)
        if exp is None:
            return False
        if exp <= now:
            _revoked_jti.pop(jti, None)
            return False
        return True


# Access Token (JWT HS256)

def create_access_token(user_id: int, phone: str, username: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MIN)
    payload: dict[str, Any] = {
        "sub":      str(user_id),
        "phone":    phone,
        "username": username,
        "iat":      now,
        "exp":      exp,
        "jti":      secrets.token_hex(16),
        "typ":      "access",
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
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {e}")
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
        user_id: int, db: Session,
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
    db.add(RefreshToken(
        user_id=user_id,
        token_hash=hash_token(raw),
        expires_at=exp,
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return raw, exp


def verify_refresh_token(raw: str, db: Session) -> User:
    token_hash = hash_token(raw)
    rec = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked_at.is_(None),
        RefreshToken.expires_at > datetime.now(timezone.utc),
        ).first()
    if not rec:
        raise HTTPException(401, "Refresh token is invalid or expired")
    user = db.query(User).filter(User.id == rec.user_id, User.is_active == True).first()
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
    user = db.query(User).filter(
        User.id == int(payload["sub"]),
        User.is_active == True,
        ).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user


async def get_user_ws(token: str, db: Session) -> User:
    """For WebSocket — token is passed as a query parameter."""
    payload = decode_access_token(token)
    user = db.query(User).filter(
        User.id == int(payload["sub"]),
        User.is_active == True,
        ).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user