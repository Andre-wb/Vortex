"""
rooms_crud — CRUD operations for rooms: create, read, update, delete, leave.
"""

from __future__ import annotations

import io
import logging
import os
import secrets as _secrets

from fastapi import Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.chats.rooms.helpers import (
    RoomCreate,
    RoomUpdate,
    _invalidate_room_escrows,
    _require_member,
    _room_dict,
    router,
)
from app.chats.rooms.settings_backend import (
    ROOM_LIMITS,
    room_avatar_given,
    room_description_read,
    room_name_read,
    room_replication_mode,
    room_settings_parse,
)
from app.database import get_db
from app.models import User
from app.models_rooms import EncryptedRoomKey, Message, Room, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.utilites.utils import generative_invite_code

logger = logging.getLogger(__name__)


def _random_aes256_hex() -> str:
    """Return 32 random bytes as 64 hex chars — for auto-provisioning
    server-side public-room keys when the client didn't send one."""
    return _secrets.token_hex(32)


# Room creation


@router.post("", status_code=201)
async def create_room(
    body: RoomCreate,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Creates a new room.

    Client must provide encrypted_room_key — room key encrypted with
    ECIES using the creator's X25519 public key. Server stores the encrypted blob
    and cannot decrypt it without the creator's private key.

    Example (JavaScript client):
      const roomKey    = crypto.getRandomValues(new Uint8Array(32));
      const encKey     = await eciesEncrypt(roomKey, myPubkeyHex);
      // encKey = {ephemeral_pub: "...", ciphertext: "..."}
      await fetch("/api/rooms", {method:"POST", body: JSON.stringify({
        name: "General",
        encrypted_room_key: encKey
      })})
    """
    if not u.x25519_public_key:
        raise HTTPException(400, "X25519 public key required to create a room")

    name = room_name_read(body.name)
    if name is None:
        raise HTTPException(400, "Invalid room name")
    description = room_description_read(body.description)
    if description is None:
        raise HTTPException(400, "Invalid room description")

    # Validate ECIES payload (классика или post-quantum гибрид)
    wrapped = body.encrypted_room_key.parsed()
    if wrapped is None:
        raise HTTPException(400, "Invalid encrypted_room_key format")

    # Free-tier cap on rooms with >100-member capacity (the default
    # max_members is 200). Premium users are unrestricted. A free user
    # can still participate in any number of rooms, they just can't
    # *create* more than ``max_big_groups`` of the large kind themselves.
    from app.security.limits import get_limits_for_user

    tier = await get_limits_for_user(u)
    if tier.max_big_groups > 0:
        # ``Room`` is already imported from ``app.models_rooms`` at the top
        # of this module — reuse it directly for the tier check.
        existing_big = (
            db.query(Room).filter(Room.creator_id == u.id, Room.max_members > tier.big_group_threshold).count()
        )
        if existing_big >= tier.max_big_groups:
            raise HTTPException(
                402,
                {
                    "error": "big_group_limit_reached",
                    "limit": tier.max_big_groups,
                    "big_group_threshold": tier.big_group_threshold,
                    "tier": "free",
                    "upgrade_hint": "Vortex Premium removes the limit on large groups.",
                },
            )

    # Create room without room_key — server does not store key in plaintext
    room = Room(
        name=name,
        description=description,
        creator_id=u.id,
        is_private=body.is_private,
        is_voice=body.is_voice,
        invite_code=generative_invite_code(8),
        max_members=ROOM_LIMITS["default_max_members"],
        avatar_emoji=room_avatar_given(body.is_voice),
        # room_key intentionally absent
    )
    db.add(room)
    db.flush()  # get room.id

    # Create owner member
    db.add(RoomMember(room_id=room.id, user_id=u.id, role=RoomRole.OWNER))

    # Save encrypted key for creator
    db.add(
        EncryptedRoomKey(
            room_id=room.id,
            user_id=u.id,
            ephemeral_pub=wrapped.ephemeral_pub,
            ciphertext=wrapped.ciphertext,
            kyber_ciphertext=wrapped.kyber_ciphertext,
            recipient_pub=u.x25519_public_key,
        )
    )

    # auto-escrow: every public room gets a server-held symmetric
    # key so new joiners and offline catch-up work without waiting for an
    # online peer. Private rooms keep the pure ECIES-per-member flow.
    if not body.is_private:
        from app.chats.rooms.public_keys import store_public_key_and_propagate

        await store_public_key_and_propagate(
            room_id=room.id,
            key_hex=(body.public_room_key_hex or _random_aes256_hex()),
            algorithm="aes-256-gcm",
            db=db,
            rotated=False,
        )

    db.commit()
    db.refresh(room)

    # Auto-add antispam bot to new rooms (skip DMs — they must have exactly 2 members)
    if not getattr(room, "is_dm", False):
        from app.bots.antispam_bot import add_antispam_bot_to_room

        add_antispam_bot_to_room(room.id, db)

    logger.info(f"Room created: '{room.name}' (id={room.id}) by {u.username}")

    return JSONResponse(
        status_code=201,
        content={
            **_room_dict(room),
            "has_key": True,  # creator already has the key
        },
    )


# Standard room operations


@router.get("/my")
async def my_rooms(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    members = db.query(RoomMember).filter(RoomMember.user_id == u.id, RoomMember.is_banned.is_(False)).all()
    member_map = {m.room_id: m for m in members}
    ids = list(member_map.keys())
    rooms = db.query(Room).filter(Room.id.in_(ids), Room.is_dm.is_(False), Room.is_channel.is_(False)).all()

    # Check key availability for each room
    key_set = {
        ek.room_id
        for ek in db.query(EncryptedRoomKey)
        .filter(
            EncryptedRoomKey.user_id == u.id,
            EncryptedRoomKey.room_id.in_(ids),
        )
        .all()
    }

    result = []
    for r in rooms:
        d = {**_room_dict(r), "has_key": r.id in key_set}
        # Count unread messages
        m = member_map.get(r.id)
        last_read = m.last_read_message_id or 0 if m else 0
        d["unread_count"] = (
            db.query(func.count(Message.id))
            .filter(
                Message.room_id == r.id,
                Message.id > last_read,
            )
            .scalar()
            or 0
        )
        d["is_muted"] = m.is_muted if m else False
        d["my_role"] = m.role.value if m else None
        result.append(d)

    return {"rooms": result}


@router.get("/public")
async def public_rooms(
    q: str = "",
    type: str = "all",  # all | group | channel | voice
    min_members: int = 0,
    sort: str = "newest",  # newest | popular | online
    offset: int = 0,
    limit: int = 40,
    db: Session = Depends(get_db),
):
    """Catalog of public rooms with filtering and pagination."""
    qs = db.query(Room).filter(Room.is_private.is_(False))

    if type == "group":
        qs = qs.filter(Room.is_channel.is_(False), Room.is_voice.is_(False))
    elif type == "channel":
        qs = qs.filter(Room.is_channel.is_(True))
    elif type == "voice":
        qs = qs.filter(Room.is_voice.is_(True))

    if q:
        pattern = f"%{q}%"
        qs = qs.filter(Room.name.ilike(pattern) | Room.description.ilike(pattern))

    rooms_all = qs.all()

    if min_members > 0:
        rooms_all = [r for r in rooms_all if r.member_count() >= min_members]

    if sort == "popular":
        rooms_all.sort(key=lambda r: r.member_count(), reverse=True)
    elif sort == "online":
        rooms_all.sort(key=lambda r: len(manager.get_online_users(r.id)), reverse=True)
    else:
        rooms_all.sort(key=lambda r: r.created_at or "", reverse=True)

    total = len(rooms_all)
    page = rooms_all[offset : offset + max(1, min(limit, 100))]
    return {"rooms": [_room_dict(r) for r in page], "total": total, "offset": offset}


@router.get("/{room_id}")
async def get_room(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)
    _require_member(room_id, u.id, db)

    # Add current user's role for frontend
    member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == u.id,
        )
        .first()
    )
    d = _room_dict(r)
    d["my_role"] = member.role.value if member else None
    return d


# Room settings update


@router.put("/{room_id}")
async def update_room(
    room_id: int,
    body: RoomUpdate,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Updates room settings. OWNER or ADMIN only.
    """
    actor = _require_member(room_id, u.id, db)
    if actor.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Insufficient permissions to change settings")

    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)

    settings = room_settings_parse(body.model_dump_json())
    if settings.refusal:
        raise HTTPException(400, settings.refusal)

    if settings.name is not None:
        r.name = settings.name
    if settings.description is not None:
        r.description = settings.description
    if settings.avatar_emoji is not None:
        r.avatar_emoji = settings.avatar_emoji
    if body.is_private is not None:
        prev_private = bool(r.is_private)
        r.is_private = body.is_private
        # Public → private flip: wipe the server-held room key so latecomers
        # can't pull it from the DB. Clients are expected to rotate via the
        # existing ECIES flow.
        if body.is_private and not prev_private:
            from app.chats.rooms.public_keys import invalidate_and_propagate

            await invalidate_and_propagate(room_id, db)
        # Private → public flip: auto-provision a fresh server-held key so
        # the room behaves like a public channel without the user having
        # to do anything in Settings. A brand-new key is generated — we
        # deliberately do NOT reuse the old E2E key so past private history
        # stays private (old messages remain decryptable only by members
        # who already have the E2E key via ECIES).
        elif prev_private and not body.is_private:
            from app.chats.rooms.public_keys import store_public_key_and_propagate

            await store_public_key_and_propagate(
                room_id=room_id,
                key_hex=_random_aes256_hex(),
                algorithm="aes-256-gcm",
                db=db,
                rotated=False,
            )
    if settings.auto_delete_given:
        r.auto_delete_seconds = settings.auto_delete_seconds
    if settings.slow_mode_seconds is not None:
        r.slow_mode_seconds = settings.slow_mode_seconds
    if body.antispam_enabled is not None:
        r.antispam_enabled = body.antispam_enabled

        # Auto-add/remove antispam bot from room
        from app.bots.antispam_bot import add_antispam_bot_to_room, remove_antispam_bot_from_room

        if body.antispam_enabled:
            add_antispam_bot_to_room(room_id, db)
        else:
            remove_antispam_bot_from_room(room_id, db)

    if settings.antispam_config is not None:
        r.antispam_config = settings.antispam_config
    elif settings.antispam_config_refused:
        logger.warning("Room %s: invalid antispam_config JSON, keeping previous", room_id)

    if body.discussion_enabled is not None:
        r.discussion_enabled = body.discussion_enabled

    # Channel-specific fields
    if settings.reactions_type is not None:
        r.reactions_type = settings.reactions_type
    if settings.allowed_reactions is not None:
        r.allowed_reactions = settings.allowed_reactions
    if body.admin_signatures is not None:
        r.admin_signatures = body.admin_signatures
    if body.copy_protection is not None:
        r.copy_protection = body.copy_protection
    if body.silent_default is not None:
        r.silent_default = body.silent_default
    if body.join_approval is not None:
        r.join_approval = body.join_approval
    if body.hashtags_enabled is not None:
        r.hashtags_enabled = body.hashtags_enabled

    db.commit()
    db.refresh(r)

    logger.info(f"Room {room_id} updated by {u.username}")

    # Notify members about settings change
    await manager.broadcast_to_room(
        room_id,
        {
            "type": "room_updated",
            "room": _room_dict(r),
        },
    )

    return _room_dict(r)


# Cross-node replication toggle (owner-only, DM-forbidden)


class ReplicationBody(BaseModel):
    mode: str = ""


@router.patch("/{room_id}/replication")
async def set_room_replication(
    room_id: int,
    body: ReplicationBody,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Flip cross-node replication for a room. OWNER only.
    Forbidden for DMs — they stay strictly local (backup+recovery only).

    Flipping to 'federated' does NOT back-fill existing messages; only
    new envelopes are replicated from this moment on. Clients must show
    a metadata-leak warning banner to participants.
    """
    actor = _require_member(room_id, u.id, db)
    if actor.role != RoomRole.OWNER:
        raise HTTPException(403, "Only the room owner can change replication")

    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)
    if r.is_dm:
        raise HTTPException(400, "DMs cannot be replicated across nodes")

    mode = room_replication_mode(body.mode)
    if mode is None:
        raise HTTPException(400, "Invalid replication mode")

    prev = getattr(r, "replication_mode", "none") or "none"
    r.replication_mode = mode
    db.commit()
    db.refresh(r)

    logger.info(
        "Room %s replication_mode: %s -> %s (owner=%s)",
        room_id,
        prev,
        mode,
        u.username,
    )

    # Notify all online members so their UI updates (banner appears/hides
    # for everyone at once).
    await manager.broadcast_to_room(
        room_id,
        {
            "type": "room_replication_changed",
            "room_id": room_id,
            "replication_mode": mode,
        },
    )

    return {"room_id": room_id, "replication_mode": mode}


@router.post("/{room_id}/avatar")
async def upload_room_avatar(
    room_id: int,
    file: UploadFile = File(...),
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Uploads room avatar. OWNER or ADMIN only.
    Pattern similar to /api/authentication/avatar.
    """
    actor = _require_member(room_id, u.id, db)
    if actor.role not in (RoomRole.ADMIN, RoomRole.OWNER):
        raise HTTPException(403, "Insufficient permissions")

    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)

    from PIL import Image

    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "Max 5 MB")

    try:
        img = Image.open(io.BytesIO(content))
        img = img.convert("RGB")
        img.thumbnail((256, 256))
    except Exception:
        raise HTTPException(400, "Invalid image format") from None

    os.makedirs("uploads/room_avatars", exist_ok=True)
    filename = f"{_secrets.token_hex(16)}.jpg"
    path = f"uploads/room_avatars/{filename}"
    img.save(path, "JPEG", quality=85)

    r.avatar_url = f"/uploads/room_avatars/{filename}"
    db.commit()

    logger.info(f"Room {room_id} avatar uploaded by {u.username}")

    # Notify members
    await manager.broadcast_to_room(
        room_id,
        {
            "type": "room_updated",
            "room": _room_dict(r),
        },
    )

    return {"ok": True, "avatar_url": r.avatar_url}


@router.delete("/{room_id}/leave")
async def leave_room(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    m = db.query(RoomMember).filter(RoomMember.room_id == room_id, RoomMember.user_id == u.id).first()
    if not m:
        raise HTTPException(404)

    # Delete member's encrypted key
    db.query(EncryptedRoomKey).filter(
        EncryptedRoomKey.room_id == room_id,
        EncryptedRoomKey.user_id == u.id,
    ).delete()

    r = db.query(Room).filter(Room.id == room_id).first()

    db.delete(m)
    db.flush()

    # Count remaining members AFTER removing the member
    remaining = db.query(RoomMember).filter(RoomMember.room_id == room_id).count() if r else 0

    if m.role == RoomRole.OWNER and r and remaining <= 0:
        db.delete(r)
        db.commit()
        return {"left": True, "room_deleted": True}

    db.commit()

    # Key rotation — the leaving member won't be able to decrypt new messages
    # For DMs rotation is not needed — room is deleted along with the member
    if r and not r.is_dm:
        _invalidate_room_escrows(room_id, db)  # escrow'ы на старый ключ устарели
        db.commit()
        await manager.broadcast_to_room(room_id, {"type": "key_rotated"})
        logger.info(f"Room key rotated after leave in room {room_id}")

    return {"left": True, "room_deleted": False}


@router.delete("/{room_id}")
async def delete_room(
    room_id: int,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    m = _require_member(room_id, u.id, db)
    if m.role != RoomRole.OWNER:
        raise HTTPException(403, "Only the owner can delete the room")
    r = db.query(Room).filter(Room.id == room_id).first()
    if not r:
        raise HTTPException(404)
    await manager.broadcast_to_room(room_id, {"type": "room_deleted"})
    db.delete(r)
    db.commit()
    return {"ok": True}
