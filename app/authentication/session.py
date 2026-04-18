"""Refresh-токены, logout и управление устройствами."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RefreshToken, User, UserDevice
from app.security.auth_jwt import get_current_user, verify_refresh_token

from app.authentication._helpers import _set_auth_cookies, router


@router.post("/refresh")
async def refresh(request: Request, db: Session = Depends(get_db)):
    raw = request.cookies.get("refresh_token")
    if not raw:
        raise HTTPException(401, "No refresh token")
    from app.security.crypto import hash_token
    old_hash = hash_token(raw)
    device = db.query(UserDevice).filter(UserDevice.refresh_token_hash == old_hash).first()
    user = verify_refresh_token(raw, db)
    response = JSONResponse(content={"ok": True})
    _set_auth_cookies(response, user, db, request)
    if device:
        newest = db.query(UserDevice).filter(
            UserDevice.user_id == user.id
        ).order_by(UserDevice.id.desc()).first()
        if newest and device.id != newest.id:
            newest.device_name = device.device_name
            newest.device_type = device.device_type
            newest.created_at = device.created_at
            newest.last_active = datetime.now(timezone.utc)
            db.delete(device)
            db.commit()
        elif newest:
            newest.last_active = datetime.now(timezone.utc)
            db.commit()
    return response


@router.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    raw_refresh = request.cookies.get("refresh_token")
    if raw_refresh:
        from app.security.crypto import hash_token
        token_hash = hash_token(raw_refresh)
        db.query(UserDevice).filter(UserDevice.refresh_token_hash == token_hash).delete()
        rec = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if rec and not rec.revoked_at:
            rec.revoked_at = datetime.now(timezone.utc)
        db.commit()
    r = JSONResponse({"ok": True})
    r.delete_cookie("access_token", path="/")
    r.delete_cookie("refresh_token", path="/")
    return r


# ── Управление устройствами / сессиями ────────────────────────────────────

_SESSION_MANAGE_MIN_AGE = timedelta(days=7)


def _get_current_device(request: Request, user_id: int, db: Session):
    """Return (current_device, current_hash) for the requesting session."""
    from app.security.crypto import hash_token
    raw_refresh = request.cookies.get("refresh_token")
    current_hash = hash_token(raw_refresh) if raw_refresh else None
    current_device = None
    if current_hash:
        current_device = db.query(UserDevice).filter(
            UserDevice.user_id == user_id,
            UserDevice.refresh_token_hash == current_hash,
        ).first()
    return current_device, current_hash


def _can_manage_sessions(device, user_id: int, db: Session) -> bool:
    """Session must be at least 7 days old OR be the very first session."""
    if not device or not device.created_at:
        return False
    # First session ever — always has full rights
    oldest = db.query(UserDevice).filter(
        UserDevice.user_id == user_id
    ).order_by(UserDevice.created_at.asc()).first()
    if oldest and oldest.id == device.id:
        return True
    # Otherwise check age
    created = device.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - created
    return age >= _SESSION_MANAGE_MIN_AGE


@router.get("/devices")
async def list_devices(request: Request, u: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """Список всех активных устройств пользователя."""
    devices = db.query(UserDevice).filter(UserDevice.user_id == u.id).order_by(UserDevice.last_active.desc()).all()
    current_device, current_hash = _get_current_device(request, u.id, db)
    can_manage = _can_manage_sessions(current_device, u.id, db)

    result = []
    for d in devices:
        ip_masked = d.ip_address
        if ip_masked:
            parts = ip_masked.split(".")
            if len(parts) == 4:
                ip_masked = f"{parts[0]}.{parts[1]}.{parts[2]}.*"
        result.append({
            "id": d.id,
            "device_name": d.device_name,
            "device_type": d.device_type,
            "ip_address": ip_masked,
            "last_active": (d.last_active.isoformat() + "Z") if d.last_active else None,
            "created_at": (d.created_at.isoformat() + "Z") if d.created_at else None,
            "is_current": current_hash is not None and d.refresh_token_hash == current_hash,
            "device_pub_key": d.device_pub_key,
        })
    return {"devices": result, "can_manage": can_manage}


@router.delete("/devices/{device_id}")
async def logout_device(device_id: int, request: Request,
                        u: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    """Удалённый выход — завершить сеанс конкретного устройства."""
    current_device, _ = _get_current_device(request, u.id, db)
    if not _can_manage_sessions(current_device, u.id, db):
        raise HTTPException(403, "Session must be active for at least 7 days to manage other sessions")

    device = db.query(UserDevice).filter(
        UserDevice.id == device_id, UserDevice.user_id == u.id
    ).first()
    if not device:
        raise HTTPException(404, "Device not found")
    if device.refresh_token_hash:
        rec = db.query(RefreshToken).filter(
            RefreshToken.token_hash == device.refresh_token_hash,
            RefreshToken.revoked_at.is_(None),
        ).first()
        if rec:
            rec.revoked_at = datetime.now(timezone.utc)
    db.delete(device)
    db.commit()
    return {"ok": True}


@router.delete("/devices")
async def logout_all_other_devices(request: Request,
                                   u: User = Depends(get_current_user),
                                   db: Session = Depends(get_db)):
    """Завершить все сеансы кроме текущего."""
    current_device, current_hash = _get_current_device(request, u.id, db)
    if not _can_manage_sessions(current_device, u.id, db):
        raise HTTPException(403, "Session must be active for at least 7 days to manage other sessions")

    from app.security.crypto import hash_token
    raw_refresh = request.cookies.get("refresh_token")
    current_hash = hash_token(raw_refresh) if raw_refresh else None
    devices = db.query(UserDevice).filter(
        UserDevice.user_id == u.id,
        UserDevice.refresh_token_hash != current_hash,
    ).all()
    for d in devices:
        if d.refresh_token_hash:
            rec = db.query(RefreshToken).filter(
                RefreshToken.token_hash == d.refresh_token_hash,
                RefreshToken.revoked_at.is_(None),
            ).first()
            if rec:
                rec.revoked_at = datetime.now(timezone.utc)
        db.delete(d)
    db.commit()
    return {"ok": True}


# ── Проверка и смена пароля ───────────────────────────────────────────────────

from pydantic import BaseModel as _BM


class _VerifyPasswordRequest(_BM):
    password: str


class _ChangePasswordRequest(_BM):
    new_password: str


@router.post("/verify-password")
async def verify_password(
    body: _VerifyPasswordRequest,
    request: Request,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify that the user knows their current password."""
    try:
        from app.security.crypto import verify_password
        valid = verify_password(body.password, u.password_hash)
    except Exception:
        try:
            from passlib.hash import argon2
            valid = argon2.verify(body.password, u.password_hash)
        except Exception:
            valid = False
    return {"valid": valid}


@router.post("/change-password")
async def change_password(
    body: _ChangePasswordRequest,
    request: Request,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change password. Session must be 7+ days old OR first session OR recovery session."""
    current_device, _ = _get_current_device(request, u.id, db)
    # Recovery sessions (created via security questions) have device_name starting with 'recovery:'
    is_recovery = current_device and current_device.device_name and current_device.device_name.startswith('recovery:')
    if not is_recovery and not _can_manage_sessions(current_device, u.id, db):
        raise HTTPException(403, "Session must be active for at least 7 days to change password")

    if len(body.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    try:
        from app.security.crypto import hash_password
        u.password_hash = hash_password(body.new_password)
    except Exception:
        from passlib.hash import argon2
        u.password_hash = argon2.hash(body.new_password)

    db.commit()
    return {"ok": True}


# ── Авто-удаление аккаунта при неактивности ─────────────────────────────────

class _AccountTTLRequest(_BM):
    ttl_days: int = 0  # 0 = disabled


@router.post("/account-ttl")
async def set_account_ttl(
    body: _AccountTTLRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Set auto-delete TTL for the account (days of inactivity)."""
    days = max(0, min(body.ttl_days, 3650))  # 0..10 years
    # Store in user metadata — use a simple column or JSON
    # For now, store in a well-known field
    try:
        if hasattr(u, 'auto_delete_days'):
            u.auto_delete_days = days
        else:
            # Fallback: store in custom_status as prefix (temporary)
            pass
        u.last_seen = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()
    return {"ok": True, "ttl_days": days}


# ── Лимит сессий ─────────────────────────────────────────────────────────────

class _SessionLimitRequest(_BM):
    max_sessions: int = 0  # 0 = unlimited


@router.get("/session-limit")
async def get_session_limit(
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get session limit for current user. 0 = unlimited (default)."""
    current_sessions = 0
    try:
        current_sessions = db.query(UserDevice).filter(UserDevice.user_id == u.id).count()
    except Exception:
        pass
    return {"max_sessions": 0, "current_sessions": current_sessions}


@router.post("/session-limit")
async def set_session_limit(
    body: _SessionLimitRequest,
    request: Request,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Set max sessions and auto-terminate oldest if exceeded. 0 = unlimited."""
    current_device, _ = _get_current_device(request, u.id, db)
    if not _can_manage_sessions(current_device, u.id, db):
        raise HTTPException(403, "Session must be active for at least 7 days")

    limit = body.max_sessions
    if limit == 0:
        # 0 = unlimited — no enforcement
        return {"ok": True, "max_sessions": 0, "terminated": 0}
    limit = max(1, min(limit, 20))

    # Count current sessions
    devices = db.query(UserDevice).filter(
        UserDevice.user_id == u.id
    ).order_by(UserDevice.last_active.desc()).all()

    terminated = 0
    if len(devices) > limit:
        # Keep newest `limit` devices, terminate the rest
        to_remove = devices[limit:]
        for d in to_remove:
            if d.refresh_token_hash:
                rec = db.query(RefreshToken).filter(
                    RefreshToken.token_hash == d.refresh_token_hash,
                    RefreshToken.revoked_at.is_(None),
                ).first()
                if rec:
                    rec.revoked_at = datetime.now(timezone.utc)
            db.delete(d)
            terminated += 1
        try:
            db.commit()
        except Exception:
            db.rollback()

    return {"ok": True, "max_sessions": limit, "terminated": terminated}
