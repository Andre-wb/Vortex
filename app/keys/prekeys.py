"""
app/keys/prekeys.py — API for publishing and retrieving Pre-Key Bundles (X3DH / Double Ratchet).

Endpoints:
  POST /api/keys/prekeys/publish   — upload SPK + batch of OPKs.
  GET  /api/keys/prekeys/{user_id} — retrieve Pre-Key Bundle (consumes one OPK).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models.prekeys import OneTimePreKey, PreKeyBundle
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/keys/prekeys", tags=["prekeys"])

# Maximum number of OPKs per single publish request.
_MAX_OPK_BATCH = 100

# Minimum recommended OPK reserve; when below this threshold
# the client should replenish the pool.
_LOW_OPK_THRESHOLD = 10


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class OneTimePreKeyUpload(BaseModel):
    """A single one-time Pre-Key for upload."""
    key_id: int = Field(..., description="Local OPK identifier (assigned by client)")
    public_key: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="X25519 public key in hex (32 bytes = 64 hex chars)",
    )


class PublishPreKeysRequest(BaseModel):
    """Request to publish a Pre-Key Bundle.

    Client sends its Identity Key, Signed Pre-Key (with signature)
    and a batch of One-Time Pre-Keys.
    """
    identity_key: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="X25519 public Identity Key in hex",
    )
    signed_prekey: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="X25519 public Signed Pre-Key in hex",
    )
    signed_prekey_sig: str = Field(
        ...,
        min_length=128,
        max_length=128,
        description="Ed25519 signature of SPK in hex (64 bytes = 128 hex chars)",
    )
    signed_prekey_id: int = Field(
        ...,
        ge=0,
        description="SPK identifier for rotation",
    )
    one_time_prekeys: List[OneTimePreKeyUpload] = Field(
        default_factory=list,
        max_length=_MAX_OPK_BATCH,
        description="Bundle of one-time Pre-Keys (up to 100)",
    )


class PreKeyBundleResponse(BaseModel):
    """Response with a user's Pre-Key Bundle."""
    user_id: int
    identity_key: str           # hex
    signed_prekey: str          # hex
    signed_prekey_sig: str      # hex
    signed_prekey_id: int
    one_time_prekey: Optional[str] = None   # hex — single OPK or None
    one_time_prekey_id: Optional[int] = None


class PreKeyStatusResponse(BaseModel):
    """Pre-Key Bundle status."""
    published: bool
    signed_prekey_id: Optional[int] = None
    available_opk_count: int = 0
    low_opk_warning: bool = False


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.post("/publish", response_model=PreKeyStatusResponse)
async def publish_prekeys(
    body: PublishPreKeysRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyStatusResponse:
    """Publishes or updates the current user's Pre-Key Bundle.

    If a record already exists — updates SPK (and signature).
    One-time keys are added to the existing pool.
    """
    try:
        ik_bytes = bytes.fromhex(body.identity_key)
        spk_bytes = bytes.fromhex(body.signed_prekey)
        sig_bytes = bytes.fromhex(body.signed_prekey_sig)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding in keys")

    if len(ik_bytes) != 32 or len(spk_bytes) != 32 or len(sig_bytes) != 64:
        raise HTTPException(status_code=400, detail="Invalid key lengths")

    # Upsert PreKeyBundle
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user.id)
        .first()
    )

    now = datetime.now(timezone.utc)

    if bundle is None:
        bundle = PreKeyBundle(
            user_id=user.id,
            identity_key=ik_bytes,
            signed_prekey=spk_bytes,
            signed_prekey_sig=sig_bytes,
            signed_prekey_id=body.signed_prekey_id,
            created_at=now,
            updated_at=now,
        )
        db.add(bundle)
    else:
        bundle.identity_key = ik_bytes
        bundle.signed_prekey = spk_bytes
        bundle.signed_prekey_sig = sig_bytes
        bundle.signed_prekey_id = body.signed_prekey_id
        bundle.updated_at = now

    # Add one-time keys
    for opk in body.one_time_prekeys:
        try:
            opk_bytes = bytes.fromhex(opk.public_key)
        except ValueError:
            logger.warning("Skipping OPK with invalid hex, key_id=%d", opk.key_id)
            continue
        if len(opk_bytes) != 32:
            logger.warning("Skipping OPK with wrong length, key_id=%d", opk.key_id)
            continue

        db.add(OneTimePreKey(
            user_id=user.id,
            key_id=opk.key_id,
            public_key=opk_bytes,
            used=False,
            created_at=now,
        ))

    db.commit()

    # Count available OPKs
    available = (
        db.query(OneTimePreKey)
        .filter(OneTimePreKey.user_id == user.id, OneTimePreKey.used == False)  # noqa: E712
        .count()
    )

    logger.info(
        "User %d published prekeys (spk_id=%d, new_opk=%d, total_opk=%d)",
        user.id, body.signed_prekey_id, len(body.one_time_prekeys), available,
    )

    return PreKeyStatusResponse(
        published=True,
        signed_prekey_id=bundle.signed_prekey_id,
        available_opk_count=available,
        low_opk_warning=available < _LOW_OPK_THRESHOLD,
    )


@router.get("/{user_id}", response_model=PreKeyBundleResponse)
async def get_prekey_bundle(
    user_id: int,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyBundleResponse:
    """Retrieves the Pre-Key Bundle for the specified user.

    Consumes (marks used=True) one One-Time Pre-Key if available.
    If OPKs are exhausted — returns bundle without OPK (acceptable per X3DH protocol).
    """
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user_id)
        .first()
    )

    if bundle is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pre-key bundle not found for user {user_id}",
        )

    # Retrieve and consume one OPK (FIFO by id)
    opk: Optional[OneTimePreKey] = (
        db.query(OneTimePreKey)
        .filter(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.used == False,  # noqa: E712
        )
        .order_by(OneTimePreKey.id)
        .first()
    )

    opk_hex: Optional[str] = None
    opk_key_id: Optional[int] = None

    if opk is not None:
        opk.used = True
        opk_hex = opk.public_key.hex()
        opk_key_id = opk.key_id
        db.commit()

        # Check remaining OPK reserve
        remaining = (
            db.query(OneTimePreKey)
            .filter(
                OneTimePreKey.user_id == user_id,
                OneTimePreKey.used == False,  # noqa: E712
            )
            .count()
        )
        if remaining < _LOW_OPK_THRESHOLD:
            logger.warning(
                "User %d has only %d OPKs left (threshold=%d) — "
                "client should replenish",
                user_id, remaining, _LOW_OPK_THRESHOLD,
            )
    else:
        logger.warning(
            "No OPKs available for user %d — X3DH will proceed without OPK",
            user_id,
        )

    return PreKeyBundleResponse(
        user_id=user_id,
        identity_key=bundle.identity_key.hex(),
        signed_prekey=bundle.signed_prekey.hex(),
        signed_prekey_sig=bundle.signed_prekey_sig.hex(),
        signed_prekey_id=bundle.signed_prekey_id,
        one_time_prekey=opk_hex,
        one_time_prekey_id=opk_key_id,
    )


@router.get("/status/me", response_model=PreKeyStatusResponse)
async def get_prekey_status(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyStatusResponse:
    """Returns the Pre-Key Bundle status for the current user.

    Useful for the client to determine whether OPK replenishment is needed.
    """
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user.id)
        .first()
    )

    if bundle is None:
        return PreKeyStatusResponse(
            published=False,
            available_opk_count=0,
            low_opk_warning=True,
        )

    available = (
        db.query(OneTimePreKey)
        .filter(OneTimePreKey.user_id == user.id, OneTimePreKey.used == False)  # noqa: E712
        .count()
    )

    return PreKeyStatusResponse(
        published=True,
        signed_prekey_id=bundle.signed_prekey_id,
        available_opk_count=available,
        low_opk_warning=available < _LOW_OPK_THRESHOLD,
    )
