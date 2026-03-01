"""
Аутентификация по номеру телефона.
При регистрации генерируется X25519 ключевая пара узла.
Публичный ключ сохраняется в БД для E2E обмена.
"""
from __future__ import annotations
import logging, re
from datetime import datetime, timezone
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.security.auth_jwt import (
    create_access_token, create_refresh_token,
    get_current_user, verify_refresh_token,
)
from app.config import Config
from app.security.crypto import get_node_public_key_hex
from app.database import get_db
from app.models import User
from app.security.security_vaidate import validate_password, validate_password_with_context, calculate_password_strength
from app.security.crypto import verify_password
import time
start = time.time()

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/authentication", tags=["authentication"])

_PHONE_RE = re.compile(r"^\+?[1-9]\d{9,14}$")
_USER_RE  = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


class RegisterRequest(BaseModel):
    phone:        str = Field(..., min_length=10, max_length=20)
    username:     str = Field(..., min_length=3,  max_length=30)
    password:     str = Field(..., min_length=8,  max_length=128)
    display_name: str = Field("", max_length=100)
    avatar_emoji: str = Field("👤", max_length=10)

    @field_validator("phone")
    @classmethod
    def v_phone(cls, v):
        c = re.sub(r"[\s\-\(\)]", "", v)
        if not _PHONE_RE.match(c):
            raise ValueError("Неверный формат номера телефона")
        return c

    @field_validator("username")
    @classmethod
    def v_username(cls, v):
        if not _USER_RE.match(v):
            raise ValueError("Только буквы, цифры и _ (3–30 символов)")
        return v.lower()


class LoginRequest(BaseModel):
    phone_or_username: str = Field(..., min_length=3, max_length=128)
    password:          str = Field(..., min_length=1, max_length=128)


class PasswordStrengthRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)


def _set_auth_cookies(response, user: User, db: Session, request: Request):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    access = create_access_token(user.id, user.phone, user.username)
    raw_ref, _ = create_refresh_token(user.id, db, ip, ua)
    for name, val, max_age in [
        ("access_token",  access,   86400),
        ("refresh_token", raw_ref,  86400 * 30),
    ]:
        response.set_cookie(
            name, val,
            httponly=True,
            secure=Config.IS_PRODUCTION,
            samesite="Lax",
            max_age=max_age,
            path="/",
        )

@router.post("/register", status_code=201)
async def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    start = time.time()
    logger.info(f"📦 Register request body: {body.dict()}")

    # Проверка уникальности телефона
    if db.query(User).filter(User.phone == body.phone).first():
        logger.error(f"❌ Phone already exists: {body.phone}")
        raise HTTPException(409, "Номер телефона уже занят")
    logger.info(f"✅ Phone unique: {time.time()-start:.3f}s")

    # Проверка уникальности username
    if db.query(User).filter(User.username == body.username).first():
        logger.error(f"❌ Username already exists: {body.username}")
        raise HTTPException(409, "Имя пользователя уже занято")
    logger.info(f"✅ Username unique: {time.time()-start:.3f}s")

    # Валидация пароля
    # ВАЖНО: HTTPException наследует от Exception.
    # Если не поймать его отдельно — raise HTTPException(422) внутри try
    # немедленно ловится except Exception и превращается в 500.
    # Решение: except HTTPException: raise — пробрасываем 4xx как есть.
    try:
        ok, msg = validate_password_with_context(body.password, body.username)
        if not ok:
            logger.error(f"❌ Password validation failed: {msg}")
            raise HTTPException(422, msg)
    except HTTPException:
        raise  # пробрасываем 422 — не перехватываем как 500
    except Exception as e:
        logger.exception("❌ Exception in validate_password_with_context")
        raise HTTPException(500, "Internal server error")
    logger.info(f"✅ Password validated: {time.time()-start:.3f}s")

    # Получение публичного ключа
    try:
        pubkey = get_node_public_key_hex(Config.KEYS_DIR)
        logger.info(f"✅ Got pubkey: {time.time()-start:.3f}s")
    except Exception as e:
        logger.exception("❌ Failed to get pubkey")
        raise HTTPException(500, "Internal server error")

    user = User(
        phone=body.phone,
        username=body.username,
        display_name=body.display_name or body.username,
        avatar_emoji=body.avatar_emoji,
        x25519_public_key=pubkey,
    )

    # Установка пароля в отдельном потоке
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, user.set_password, body.password)
        logger.info(f"✅ Password hashed: {time.time()-start:.3f}s")
    except Exception as e:
        logger.exception("❌ Error in set_password")
        raise HTTPException(500, "Internal error during password hashing")

    db.add(user)
    logger.info(f"✅ User added to session: {time.time()-start:.3f}s")

    try:
        await loop.run_in_executor(None, db.commit)
        logger.info(f"✅ Commit done: {time.time()-start:.3f}s")
    except Exception as e:
        logger.exception("❌ Commit failed")
        db.rollback()
        raise HTTPException(500, "Database error")

    db.refresh(user)
    logger.info(f"✅ User refreshed: {time.time()-start:.3f}s")

    data = {
        "ok": True,
        "user_id": user.id,
        "username": user.username,
        "phone": user.phone,
        "display_name": user.display_name,
        "avatar_emoji": user.avatar_emoji,
    }
    response = JSONResponse(status_code=201, content=data)
    _set_auth_cookies(response, user, db, request)
    logger.info(f"✅ Registration successful for {user.username} in {time.time()-start:.3f}s")
    return response

@router.post("/login")
async def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    cred = body.phone_or_username.strip()
    user = (
            db.query(User).filter(User.phone == cred).first()
            or db.query(User).filter(User.username == cred.lower()).first()
    )
    # Всегда проверяем пароль (защита от timing-атаки)
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$dummy"
    if not user:
        verify_password(body.password, dummy_hash)
        raise HTTPException(401, "Неверный телефон/имя или пароль")

    if not user.check_password(body.password):
        raise HTTPException(401, "Неверный телефон/имя или пароль")
    if not user.is_active:
        raise HTTPException(403, "Аккаунт заблокирован")

    user.last_seen = datetime.now(timezone.utc)
    db.commit()

    data = {
        "ok": True, "user_id": user.id, "username": user.username,
        "phone": user.phone, "display_name": user.display_name or user.username,
        "avatar_emoji": user.avatar_emoji,
    }
    response = JSONResponse(content=data)
    _set_auth_cookies(response, user, db, request)
    return response


@router.post("/refresh")
async def refresh(request: Request, db: Session = Depends(get_db)):
    raw = request.cookies.get("refresh_token")
    if not raw:
        raise HTTPException(401, "Нет refresh-токена")
    user = verify_refresh_token(raw, db)
    response = JSONResponse(content={"ok": True})
    _set_auth_cookies(response, user, db, request)
    return response


@router.post("/logout")
async def logout(response):
    from fastapi import Response
    r = JSONResponse({"ok": True})
    r.delete_cookie("access_token",  path="/")
    r.delete_cookie("refresh_token", path="/")
    return r


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {
        "user_id":        current_user.id,
        "phone":          current_user.phone,
        "username":       current_user.username,
        "display_name":   current_user.display_name or current_user.username,
        "avatar_emoji":   current_user.avatar_emoji,
        "x25519_pubkey":  current_user.x25519_public_key,  # для E2E
        "created_at":     current_user.created_at.isoformat(),
        "last_seen":      current_user.last_seen.isoformat(),
    }


@router.post("/password-strength")
async def password_strength(body: PasswordStrengthRequest):
    """Анализ стойкости пароля — для UI."""
    return calculate_password_strength(body.password)


@router.get("/csrf-token")
async def get_csrf_token(request: Request):
    """Возвращает текущий CSRF токен для использования в заголовке X-CSRF-Token."""
    token = request.cookies.get("csrf_token", "")
    return {"csrf_token": token}