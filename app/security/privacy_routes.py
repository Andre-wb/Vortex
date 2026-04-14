"""
Privacy API endpoints — Tor status, ephemeral identities, ZK membership, metadata padding.
"""
from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.security.auth_jwt import get_current_user
from app.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/privacy", tags=["privacy"])


# ── Models ────────────────────────────────────────────────────────────────────

class EphemeralRequest(BaseModel):
    room_id: int
    user_secret_hex: str  # 32-byte hex secret (stored on client device)


class ZKChallengeResponse(BaseModel):
    room_id: int


class ZKProofRequest(BaseModel):
    room_id: int
    commitment: str
    response: str
    blinding: str


class PadRequest(BaseModel):
    data_b64: str
    target_size: int = 0  # 0 = auto


# ── Tor ───────────────────────────────────────────────────────────────────────

@router.get("/tor/status")
async def tor_status(u: User = Depends(get_current_user)):
    """Check Tor SOCKS5 proxy availability and get our Tor exit IP."""
    from app.security.privacy import tor_proxy
    from app.security.tor_hidden_service import tor_hidden_service
    status = tor_proxy.get_status()
    if status["available"]:
        status["exit_ip"] = await tor_proxy.check_ip()
    status["hidden_service"] = tor_hidden_service.get_status()
    return status


# ── Ephemeral Identity ────────────────────────────────────────────────────────

@router.post("/ephemeral/generate")
async def generate_ephemeral(body: EphemeralRequest, u: User = Depends(get_current_user)):
    """Generate an ephemeral (unlinkable) username for a room.

    The same user_secret + room_id always produces the same name,
    but different rooms produce different names — unlinkable.
    """
    from app.security.privacy import EphemeralIdentity
    try:
        secret = bytes.fromhex(body.user_secret_hex)
    except ValueError:
        raise HTTPException(400, "Invalid hex secret")
    if len(secret) != 32:
        raise HTTPException(400, "Secret must be 32 bytes (64 hex chars)")

    username = EphemeralIdentity.generate(secret, body.room_id)
    display_name = EphemeralIdentity.generate_display_name(secret, body.room_id)
    return {
        "ephemeral_username": username,
        "ephemeral_display_name": display_name,
        "room_id": body.room_id,
    }


@router.get("/ephemeral/new-secret")
async def new_ephemeral_secret(u: User = Depends(get_current_user)):
    """Generate a new ephemeral identity secret. Store this on device ONLY."""
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    return {"secret_hex": secret.hex()}


# ── Metadata Padding ─────────────────────────────────────────────────────────

@router.post("/pad")
async def pad_data(body: PadRequest, u: User = Depends(get_current_user)):
    """Pad data to a standard size (prevents traffic analysis by message size)."""
    from app.security.privacy import MetadataPadding
    data = base64.b64decode(body.data_b64)
    if body.target_size > 0:
        padded = MetadataPadding.pad_to_fixed(data, body.target_size)
    else:
        padded = MetadataPadding.pad(data)
    return {
        "padded_b64": base64.b64encode(padded).decode(),
        "original_size": len(data),
        "padded_size": len(padded),
    }


@router.post("/unpad")
async def unpad_data(body: PadRequest, u: User = Depends(get_current_user)):
    """Remove padding from data."""
    from app.security.privacy import MetadataPadding
    padded = base64.b64decode(body.data_b64)
    data = MetadataPadding.unpad(padded)
    if data is None:
        raise HTTPException(400, "Invalid padded data")
    return {"data_b64": base64.b64encode(data).decode(), "size": len(data)}


# ── Zero-Knowledge Membership ────────────────────────────────────────────────

@router.post("/zk/challenge")
async def zk_challenge(body: ZKChallengeResponse, u: User = Depends(get_current_user)):
    """Get a challenge for zero-knowledge membership proof."""
    from app.security.privacy import ZKMembership
    challenge = ZKMembership.generate_challenge()
    return {
        "challenge_hex": challenge.hex(),
        "room_id": body.room_id,
    }


@router.post("/zk/verify")
async def zk_verify(body: ZKProofRequest, u: User = Depends(get_current_user)):
    """Verify a zero-knowledge proof of room membership.

    The server verifies the user is a member WITHOUT learning which user.
    """
    from app.security.privacy import ZKMembership
    from app.database import SessionLocal
    from app.models_rooms import RoomMember

    db = SessionLocal()
    try:
        members = db.query(RoomMember.user_id).filter(
            RoomMember.room_id == body.room_id,
            RoomMember.is_banned == False,
        ).all()
        member_ids = [m[0] for m in members]
    finally:
        db.close()

    if not member_ids:
        raise HTTPException(404, "Room not found or empty")

    # Room secret — in PoC we derive from room_id
    # In production, this would be stored securely per-room
    import hashlib
    room_secret = hashlib.sha256(f"room-secret-{body.room_id}".encode()).digest()

    challenge = bytes.fromhex(body.commitment[:64])  # reuse commitment as challenge marker

    proof = {
        "commitment": body.commitment,
        "response": body.response,
        "blinding": body.blinding,
    }

    # Generate challenge from commitment for verification
    challenge = hashlib.sha256(bytes.fromhex(body.commitment)).digest()

    valid = ZKMembership.verify_proof(room_secret, member_ids, challenge, proof)

    return {"valid": valid, "room_id": body.room_id}


@router.get("/zk/info")
async def zk_info(u: User = Depends(get_current_user)):
    """Get info about zero-knowledge membership system."""
    from app.security.privacy import ZKMembership
    return ZKMembership.get_info()


# ── Privacy Status ────────────────────────────────────────────────────────────

@router.get("/status")
async def privacy_status(u: User = Depends(get_current_user)):
    """Get overall privacy feature status."""
    from app.security.privacy import tor_proxy, MetadataPadding, EphemeralIdentity, ZKMembership
    return {
        "tor": tor_proxy.get_status(),
        "metadata_padding": {
            "enabled": True,
            "standard_sizes": MetadataPadding.STANDARD_SIZES,
        },
        "ephemeral_identities": {
            "enabled": True,
            "method": "HMAC-SHA256 per-room derivation",
        },
        "zero_knowledge_membership": ZKMembership.get_info(),
    }


# ── Show Last Seen toggle ──────────────────────────────────────────────────

class _LastSeenRequest(BaseModel):
    show_last_seen: bool


@router.get("/last-seen")
async def get_last_seen_setting(u: User = Depends(get_current_user)):
    """Get show_last_seen setting."""
    val = getattr(u, 'show_last_seen', True)
    return {"show_last_seen": val if val is not None else True}


@router.post("/last-seen")
async def set_last_seen_setting(
    body: _LastSeenRequest,
    u: User = Depends(get_current_user),
):
    """Toggle show_last_seen."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == u.id).first()
        if user:
            user.show_last_seen = body.show_last_seen
            db.commit()
    finally:
        db.close()
    return {"ok": True, "show_last_seen": body.show_last_seen}
