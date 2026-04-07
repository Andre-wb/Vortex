"""Refresh-токены, logout и управление устройствами."""
from __future__ import annotations

from datetime import datetime, timezone

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
        raise HTTPException(401, "Нет refresh-токена")
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

@router.get("/devices")
async def list_devices(request: Request, u: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """Список всех активных устройств пользователя."""
    from app.security.crypto import hash_token
    devices = db.query(UserDevice).filter(UserDevice.user_id == u.id).order_by(UserDevice.last_active.desc()).all()
    raw_refresh = request.cookies.get("refresh_token")
    current_hash = hash_token(raw_refresh) if raw_refresh else None
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
            "last_active": d.last_active.isoformat() if d.last_active else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "is_current": current_hash is not None and d.refresh_token_hash == current_hash,
            "device_pub_key": d.device_pub_key,
        })
    return {"devices": result}


@router.delete("/devices/{device_id}")
async def logout_device(device_id: int, request: Request,
                        u: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    """Удалённый выход — завершить сеанс конкретного устройства."""
    device = db.query(UserDevice).filter(
        UserDevice.id == device_id, UserDevice.user_id == u.id
    ).first()
    if not device:
        raise HTTPException(404, "Устройство не найдено")
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
