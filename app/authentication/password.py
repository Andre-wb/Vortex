"""Регистрация и парольный вход."""
from __future__ import annotations

import logging
import secrets
import threading
import time
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.models import LoginRequest, RegisterRequest, SeedLoginRequest, User
from app.security.crypto import hash_password, verify_password
from app.security.ip_privacy import raw_ip_for_ratelimit, sanitize_ip
from app.security.seed_phrase import generate_mnemonic, normalize_mnemonic, validate_mnemonic
from app.security.security_validate import validate_password_with_context

from app.authentication._helpers import (
    _AUTH_RATE_LOGIN, _AUTH_RATE_REGISTER, _DUMMY_HASH, _IS_TESTING,
    _check_auth_rate, _set_auth_cookies, router,
)

logger = logging.getLogger(__name__)


# verify-login must NOT mint cookies on a TOTP code alone — an attacker holding
# only a victim's current TOTP code (e.g. shoulder-surfed) could otherwise log
# in without knowing the password. /login records a short-lived, single-use
# server-side marker once the PASSWORD is verified and 2FA is pending; /2fa/
# verify-login then requires & consumes that marker. The client API stays
# unchanged ({user_id, code} in, {requires_2fa, user_id} out).
#
# Storage mirrors the JWT revocation store in app/security/auth_jwt.py:
#   - Redis (Config.REDIS_URL) when set → shared across workers, auto-expiring.
#   - In-process dict fallback otherwise / when Redis is unreachable.
_PW_MARKER_PREFIX = "2fa:pwok:"
_PW_MARKER_TTL = 300  # seconds (~5 min) — long enough for the user to enter the code

_pw_verified: dict[int, float] = {}      # user_id -> expiry epoch (in-memory fallback)
_pw_verified_lock = threading.Lock()


def _purge_expired_pw_markers(now_epoch: float) -> None:
    for uid, exp in list(_pw_verified.items()):
        if exp <= now_epoch:
            _pw_verified.pop(uid, None)


def mark_password_verified(user_id: int) -> None:
    """Record that ``user_id`` just passed the password step and owes only 2FA."""
    r = _get_2fa_redis()
    if r is not None:
        try:
            r.setex(_PW_MARKER_PREFIX + str(user_id), _PW_MARKER_TTL, "1")
            return
        except Exception as e:
            logger.warning("2FA pw-marker: Redis SETEX failed (%s) — using local store", e)
    now = time.time()
    with _pw_verified_lock:
        _purge_expired_pw_markers(now)
        _pw_verified[user_id] = now + _PW_MARKER_TTL


def has_password_verified(user_id: int) -> bool:
    """Return True iff a live password-verified marker exists (non-consuming peek).

    Used so a wrong TOTP code does not burn the marker — the user can retry
    the code (subject to the existing TOTP rate limit) without re-entering the
    password.
    """
    r = _get_2fa_redis()
    if r is not None:
        try:
            if r.exists(_PW_MARKER_PREFIX + str(user_id)):
                return True
            # Fall through to also check local store (marker may have been
            # written while Redis was briefly down on this worker).
        except Exception as e:
            logger.warning("2FA pw-marker: Redis EXISTS failed (%s) — using local store", e)
    now = time.time()
    with _pw_verified_lock:
        exp = _pw_verified.get(user_id)
        if exp is None:
            return False
        if exp <= now:
            _pw_verified.pop(user_id, None)
            return False
        return True


def consume_password_verified(user_id: int) -> None:
    """Delete the password-verified marker (single-use) after a successful 2FA step."""
    r = _get_2fa_redis()
    if r is not None:
        try:
            r.delete(_PW_MARKER_PREFIX + str(user_id))
        except Exception as e:
            logger.warning("2FA pw-marker: Redis DELETE failed (%s) — clearing local store", e)
    with _pw_verified_lock:
        _pw_verified.pop(user_id, None)


# Reuse the project's Redis client/init pattern from auth_jwt for the marker store.
def _get_2fa_redis():
    from app.security.auth_jwt import _get_redis
    return _get_redis()


@router.post("/register", status_code=201)
async def register(body: RegisterRequest, request: Request,
                   db: Session = Depends(get_db)):
    import asyncio

    ip = raw_ip_for_ratelimit(request)
    if not _check_auth_rate(ip, _AUTH_RATE_REGISTER):
        raise HTTPException(429, "Too many registration attempts. Please wait a minute.")

    reg_mode = "open" if _IS_TESTING else Config.REGISTRATION_MODE
    if reg_mode == "closed":
        raise HTTPException(403, "Registration is closed")
    elif reg_mode == "invite":
        if not body.invite_code:
            raise HTTPException(403, "Invite code required for registration")
        supplied = body.invite_code.strip().upper()
        expected = Config.INVITE_CODE_NODE.upper()
        if not expected:
            raise HTTPException(403, "Invite code not configured on this node")
        if not secrets.compare_digest(supplied, expected):
            raise HTTPException(403, "Invalid invite code")
    elif reg_mode != "open":
        raise HTTPException(403, "Registration is unavailable")

    # collapse the per-field "X already taken" responses into a single
    # non-attributing message so registration cannot be used to enumerate which
    # phones / usernames / emails / keys already exist on the node. The 409
    # status is preserved for the client.
    _IDENTIFIER_TAKEN = "Registration failed: identifier unavailable"
    if body.phone and db.query(User).filter(User.phone == body.phone).first():
        raise HTTPException(409, _IDENTIFIER_TAKEN)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, _IDENTIFIER_TAKEN)
    if db.query(User).filter(User.x25519_public_key == body.x25519_public_key).first():
        raise HTTPException(409, _IDENTIFIER_TAKEN)
    if body.email and db.query(User).filter(User.email == body.email).first():
        raise HTTPException(409, _IDENTIFIER_TAKEN)

    ok, msg = validate_password_with_context(body.password, body.username)
    if not ok:
        raise HTTPException(422, msg)

    user = User(
        phone=body.phone,
        username=body.username,
        display_name=body.display_name or body.username,
        avatar_emoji=body.avatar_emoji,
        x25519_public_key=body.x25519_public_key,
        email=body.email,
        network_mode=Config.NETWORK_MODE,
    )

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, user.set_password, body.password)

    db.add(user)
    try:
        await loop.run_in_executor(None, db.commit)
    except Exception:
        db.rollback()
        logger.exception("Register commit failed")
        raise HTTPException(500, "Database error")

    db.refresh(user)

    seed_phrase = None
    if not body.phone:
        seed_phrase = generate_mnemonic()
        user.seed_phrase_hash = hash_password(normalize_mnemonic(seed_phrase))
        db.commit()
        db.refresh(user)
        logger.info("Anonymous registration: %s (seed phrase issued)", user.username)

    # Auto-log X25519 key to transparency log
    try:
        from app.security.key_backup import _kt_auto_log
        _kt_auto_log(user.id, "x25519", user.x25519_public_key, None, db)
    except Exception:
        pass  # non-critical

    kyber_secret_key_hex = None
    try:
        from app.security.post_quantum import Kyber768, pq_available
        if pq_available():
            k_pub, k_sk = Kyber768.keygen()
            user.kyber_public_key = k_pub.hex()
            kyber_secret_key_hex = k_sk.hex()
            db.commit()
            db.refresh(user)
            logger.info("Registered: %s pubkey=%s... kyber=yes",
                        user.username, user.x25519_public_key[:16])
        else:
            logger.warning("Registered: %s pubkey=%s... kyber=UNAVAILABLE (no PQ library)",
                           user.username, user.x25519_public_key[:16])
    except Exception as e:
        logger.warning("Kyber keygen failed for %s: %s", user.username, e)

    data = {
        "ok": True,
        "user_id": user.id,
        "username": user.username,
        "phone": user.phone,
        "display_name": user.display_name,
        "avatar_emoji": user.avatar_emoji,
        "avatar_url": user.avatar_url,
        "email": user.email,
        "x25519_public_key": user.x25519_public_key,
        "kyber_public_key": user.kyber_public_key,
        "network_mode": user.network_mode or "local",
        "custom_status": user.custom_status,
        "status_emoji": user.status_emoji,
        "presence": user.presence or "online",
        "created_at": user.created_at.isoformat() if user.created_at else "",
    }
    if seed_phrase:
        data["seed_phrase"] = seed_phrase
        data["seed_phrase_warning"] = (
            "Write down these 24 words on paper or save them in a safe place. "
            "This is the only key to your account. The server does NOT store the phrase — "
            "recovery without it is impossible."
        )
    response = JSONResponse(status_code=201, content=data)
    _set_auth_cookies(response, user, db, request)
    return response


@router.post("/login")
async def login(body: LoginRequest, request: Request,
                db: Session = Depends(get_db)):
    """Классический вход по паролю."""
    ip = raw_ip_for_ratelimit(request)
    if not _check_auth_rate(ip, _AUTH_RATE_LOGIN):
        raise HTTPException(429, "Too many login attempts. Please wait a minute.")

    cred = body.phone_or_username.strip()
    user = (
        db.query(User).filter(User.phone == cred).first()
        or db.query(User).filter(User.username == cred.lower()).first()
    )

    import asyncio as _aio

    if not user:
        try:
            await _aio.get_event_loop().run_in_executor(
                None, verify_password, body.password, _DUMMY_HASH)
        except Exception:
            pass
        raise HTTPException(401, "Invalid phone/username or password")

    pw_ok = await _aio.get_event_loop().run_in_executor(
        None, user.check_password, body.password)
    if not pw_ok:
        raise HTTPException(401, "Invalid phone/username or password")
    if not user.is_active:
        if user.banned_until and user.banned_until <= datetime.now(timezone.utc):
            user.is_active = True
            user.banned_until = None
            db.commit()
        elif user.banned_until:
            raise HTTPException(
                403, f"Account banned until {user.banned_until.strftime('%Y-%m-%d')}")
        elif (user.strike_count or 0) >= 5:
            raise HTTPException(403, "Account permanently banned")
        else:
            raise HTTPException(403, "Account is blocked")

    if user.totp_enabled and user.totp_secret:
        # FIX F7: password proven here → arm the single-use marker that
        # /2fa/verify-login requires before issuing cookies. Binds factor 1
        # (password) to factor 2 (TOTP) without any client-API change.
        mark_password_verified(user.id)
        return JSONResponse(content={"requires_2fa": True, "user_id": user.id})

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


@router.post("/login-seed")
async def login_with_seed(body: SeedLoginRequest, request: Request,
                          db: Session = Depends(get_db)):
    """Вход по username + seed phrase (для анонимных аккаунтов без телефона)."""
    ip = raw_ip_for_ratelimit(request)
    if not _check_auth_rate(ip, _AUTH_RATE_LOGIN):
        raise HTTPException(429, "Too many login attempts. Please wait a minute.")

    user = db.query(User).filter(User.username == body.username).first()

    import asyncio as _aio

    if not user or not user.seed_phrase_hash:
        # Constant-time dummy to prevent timing oracle
        try:
            await _aio.get_event_loop().run_in_executor(
                None, verify_password, "dummy", _DUMMY_HASH)
        except Exception:
            pass
        raise HTTPException(401, "Invalid username or seed phrase")

    if not validate_mnemonic(body.seed_phrase):
        raise HTTPException(422, "Invalid seed phrase (expected 24 BIP39 words)")

    normalized = normalize_mnemonic(body.seed_phrase)
    ok = await _aio.get_event_loop().run_in_executor(
        None, verify_password, normalized, user.seed_phrase_hash)
    if not ok:
        raise HTTPException(401, "Invalid username or seed phrase")

    if not user.is_active:
        raise HTTPException(403, "Account is blocked")

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
