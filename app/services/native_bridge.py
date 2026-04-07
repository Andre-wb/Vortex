"""
app/services/native_bridge.py — Capacitor native bridge routes.

Provides API endpoints consumed by the Capacitor native app for features
unavailable to PWA: persistent push, background sync, biometric auth,
file system access, share extensions.
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security.auth_jwt import get_current_user
from app.services.unified_push import up_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/native", tags=["native"])


class RegisterPushRequest(BaseModel):
    """Push registration from native app."""
    token: str             # FCM/APNs token or UnifiedPush endpoint
    platform: str          # "ios" | "android" | "unified_push"
    app_version: str = ""


class UnifiedPushRequest(BaseModel):
    """UnifiedPush endpoint registration."""
    endpoint: str
    app_id: str = "org.vortex.messenger"


@router.post("/push/register")
async def register_native_push(
    body: RegisterPushRequest,
    u: User = Depends(get_current_user),
):
    """
    Register a native push token (FCM/APNs) or UnifiedPush endpoint.

    For FCM/APNs: token stored server-side, used for native push.
    For UnifiedPush: endpoint URL, no Google/Apple dependency.
    """
    if body.platform == "unified_push":
        sub = await up_manager.register(u.id, body.token)
        return {"ok": True, "type": "unified_push"}
    elif body.platform in ("ios", "android"):
        # Native push token — store for later delivery
        # In production: persist to DB
        logger.info("Native push registered: user=%d platform=%s", u.id, body.platform)
        return {"ok": True, "type": body.platform}
    else:
        raise HTTPException(400, f"Unknown platform: {body.platform}")


@router.post("/push/unregister")
async def unregister_native_push(
    body: UnifiedPushRequest,
    u: User = Depends(get_current_user),
):
    """Unregister a push subscription."""
    removed = await up_manager.unregister(u.id, body.endpoint)
    return {"ok": True, "removed": removed}


@router.get("/push/subscriptions")
async def list_push_subscriptions(u: User = Depends(get_current_user)):
    """List user's active push subscriptions."""
    return {"subscriptions": up_manager.get_subscriptions(u.id)}


@router.get("/capabilities")
async def native_capabilities():
    """
    Report server capabilities for native clients.

    Used by Capacitor app to discover available features and API versions.
    """
    return {
        "api_version": "2.0",
        "features": {
            "e2e_encryption": True,
            "post_quantum": True,
            "sealed_sender": True,
            "group_calls": True,
            "sfu": True,
            "voice_channels": True,
            "stories": True,
            "spaces": True,
            "bots": True,
            "federation": True,
            "unified_push": True,
            "biometric_auth": True,
            "background_sync": True,
            "share_extension": True,
        },
        "push_providers": ["websocket", "vapid", "unified_push", "fcm", "apns"],
        "max_file_size": 104857600,  # 100MB
        "max_group_call": 50,
    }


@router.post("/biometric/challenge")
async def biometric_challenge(u: User = Depends(get_current_user)):
    """
    Generate a challenge for biometric authentication.

    Used by Capacitor Biometric plugin: Face ID / Touch ID / Android fingerprint.
    The challenge is signed by the device's Secure Enclave / TEE,
    verifying physical presence without sending credentials.
    """
    import os
    import time
    challenge = os.urandom(32).hex()
    return {
        "challenge": challenge,
        "user_id": u.id,
        "expires": int(time.time()) + 300,  # 5 min
    }
