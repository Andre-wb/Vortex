"""POST /v1/register and /v1/heartbeat.

Both accept a signed payload. Signature is verified against the pubkey inside
the payload, proving the caller controls the private key.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request

from ..controller_crypto import verify_signature
from ..models import (
    HeartbeatRequest,
    RegisterAck,
    RegistrationRequest,
)

router = APIRouter(prefix="/v1", tags=["register"])

# Reject registrations with a timestamp drift larger than this
MAX_CLOCK_SKEW_SEC = 300


def _within_skew(ts: int) -> bool:
    return abs(int(time.time()) - ts) <= MAX_CLOCK_SKEW_SEC


@router.post("/register", response_model=RegisterAck)
async def register(req: RegistrationRequest, request: Request) -> RegisterAck:
    payload = req.payload

    if not _within_skew(payload.timestamp):
        raise HTTPException(400, "timestamp too far from server clock")

    # Verify signature proves pubkey ownership
    if not verify_signature(
        pubkey_hex=payload.pubkey,
        signature_hex=req.signature,
        payload=payload.model_dump(),
    ):
        raise HTTPException(401, "invalid signature")

    if not payload.endpoints:
        raise HTTPException(400, "endpoints must not be empty")
    if len(payload.endpoints) > 16:
        raise HTTPException(400, "too many endpoints (max 16)")
    for ep in payload.endpoints:
        if not isinstance(ep, str) or len(ep) > 512:
            raise HTTPException(400, "invalid endpoint")

    storage = request.app.state.storage
    auto_approve = request.app.state.auto_approve

    await storage.register(
        pubkey_hex=payload.pubkey,
        endpoints=payload.endpoints,
        metadata=payload.metadata,
        approved=auto_approve,
    )
    return RegisterAck(
        ok=True,
        approved=auto_approve,
        message=None if auto_approve else "pending manual approval",
    )


@router.post("/heartbeat", response_model=RegisterAck)
async def heartbeat(req: HeartbeatRequest, request: Request) -> RegisterAck:
    payload = req.payload

    if not _within_skew(payload.timestamp):
        raise HTTPException(400, "timestamp too far from server clock")

    if not verify_signature(
        pubkey_hex=payload.pubkey,
        signature_hex=req.signature,
        payload=payload.model_dump(),
    ):
        raise HTTPException(401, "invalid signature")

    storage = request.app.state.storage
    if not await storage.heartbeat(payload.pubkey):
        raise HTTPException(404, "node not registered; call /v1/register first")

    return RegisterAck(ok=True, approved=True)
