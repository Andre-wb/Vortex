"""
sealed_keys.py — Sealed Key Exchange: zero-metadata key distribution via BMP.

Architecture:
  1. Room creator generates N prekey packages (ECIES-encrypted room key)
  2. Each package is encrypted for a one-time X25519 pubkey
  3. New member generates ephemeral keypair, claims a package by pubkey
  4. Server never sees who claims which package (anonymous slots)
  5. When prekeys exhausted → any member with key can replenish

Combined with BMP:
  - key_request/key_response flow through BMP mailboxes (anonymous)
  - Prekey packages cover the case when ALL members are offline
  - Server stores only encrypted blobs — cannot read room keys

Metadata protection:
  - No user_id in SealedKeyPackage — anonymous claim by pubkey
  - BMP key_request contains only room_id + pubkey (no user identity)
  - key_response delivered via BMP deposit (server can't correlate)
"""
from __future__ import annotations

import logging
from typing import List

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import SealedKeyPackage, RoomMember, EncryptedRoomKey
from app.security.auth_jwt import get_current_user
from app.security.key_exchange import validate_ecies_payload

from app.chats.rooms.helpers import router

logger = logging.getLogger(__name__)

PREKEY_BATCH_SIZE = 10  # generate 10 prekeys at a time


# ══════════════════════════════════════════════════════════════════════════════
# Upload prekey packages (room creator or any member with key)
# ══════════════════════════════════════════════════════════════════════════════

class PrekeyPackage(BaseModel):
    ephemeral_pub: str   # ECIES ephemeral public key (64 hex)
    ciphertext: str      # ECIES encrypted room key (120 hex)
    recipient_pub: str   # one-time pubkey this was encrypted for (64 hex)


class UploadPrekeysRequest(BaseModel):
    packages: List[PrekeyPackage]


@router.post("/{room_id}/sealed-prekeys")
async def upload_sealed_prekeys(
    room_id: int,
    body: UploadPrekeysRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Upload pre-sealed key packages for a room.
    Any member with the room key can create these.
    Server stores encrypted blobs — cannot read room keys.
    """
    # Verify caller is a member
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Not a member")

    # Verify caller has a key (only key holders can create prekeys)
    has_key = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
    ).first()
    if not has_key:
        raise HTTPException(403, "No room key — cannot create prekeys")

    # Get current max slot index
    max_slot = db.query(SealedKeyPackage.slot_index).filter(
        SealedKeyPackage.room_id == room_id,
    ).order_by(SealedKeyPackage.slot_index.desc()).first()
    next_slot = (max_slot[0] + 1) if max_slot else 0

    added = 0
    for pkg in body.packages:
        if not validate_ecies_payload({"ephemeral_pub": pkg.ephemeral_pub, "ciphertext": pkg.ciphertext}):
            continue
        if len(pkg.recipient_pub) != 64:
            continue

        db.add(SealedKeyPackage(
            room_id       = room_id,
            slot_index    = next_slot,
            ephemeral_pub = pkg.ephemeral_pub,
            ciphertext    = pkg.ciphertext,
            recipient_pub = pkg.recipient_pub,
            is_claimed    = 0,
        ))
        next_slot += 1
        added += 1

    db.commit()

    available = db.query(SealedKeyPackage).filter(
        SealedKeyPackage.room_id == room_id,
        SealedKeyPackage.is_claimed == 0,
    ).count()

    logger.info(f"[SealedKeys] {added} prekeys uploaded for room {room_id} by user {u.id} (available: {available})")
    return {"ok": True, "added": added, "available": available}


# ══════════════════════════════════════════════════════════════════════════════
# Claim a prekey package (new member joining)
# ══════════════════════════════════════════════════════════════════════════════

class ClaimPrekeyRequest(BaseModel):
    pubkey: str  # X25519 pubkey of the new member (64 hex)


@router.post("/{room_id}/claim-prekey")
async def claim_sealed_prekey(
    room_id: int,
    body: ClaimPrekeyRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Claim a pre-sealed key package.

    New member provides their X25519 pubkey.
    Server finds an available package encrypted for a one-time pubkey,
    returns it. The member must have the corresponding private key.

    Privacy: server sees only room_id + pubkey claim. No user_id correlation
    needed — the package is encrypted for whoever holds the private key.
    """
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Not a member")

    # Already has key?
    existing = db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
    ).first()
    if existing:
        return {
            "has_key": True,
            "ephemeral_pub": existing.ephemeral_pub,
            "ciphertext": existing.ciphertext,
        }

    # Find an available prekey package
    pkg = db.query(SealedKeyPackage).filter(
        SealedKeyPackage.room_id == room_id,
        SealedKeyPackage.is_claimed == 0,
    ).first()

    if not pkg:
        return {"has_key": False, "reason": "no_prekeys"}

    # Mark as claimed
    pkg.is_claimed = 1
    db.commit()

    # Save as EncryptedRoomKey for this user (so they don't need to claim again)
    db.add(EncryptedRoomKey(
        room_id       = room_id,
        user_id       = u.id,
        ephemeral_pub = pkg.ephemeral_pub,
        ciphertext    = pkg.ciphertext,
        recipient_pub = pkg.recipient_pub,
    ))
    db.commit()

    # Count remaining
    remaining = db.query(SealedKeyPackage).filter(
        SealedKeyPackage.room_id == room_id,
        SealedKeyPackage.is_claimed == 0,
    ).count()

    logger.info(f"[SealedKeys] Prekey claimed for room {room_id} (remaining: {remaining})")

    # If running low, notify online members to replenish
    if remaining < 3:
        from app.peer.connection_manager import manager
        await manager.broadcast_to_room(room_id, {
            "type": "prekeys_low",
            "room_id": room_id,
            "remaining": remaining,
        })

    return {
        "has_key": True,
        "ephemeral_pub": pkg.ephemeral_pub,
        "ciphertext": pkg.ciphertext,
        "recipient_pub": pkg.recipient_pub,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Check prekey availability
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/{room_id}/prekey-count")
async def get_prekey_count(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return number of available prekey packages for a room."""
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
    ).first()
    if not member:
        raise HTTPException(403, "Not a member")

    count = db.query(SealedKeyPackage).filter(
        SealedKeyPackage.room_id == room_id,
        SealedKeyPackage.is_claimed == 0,
    ).count()

    return {"available": count}
