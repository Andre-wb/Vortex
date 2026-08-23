"""
rooms_helpers — Shared router, Pydantic models, and helper functions for the rooms module.

All route modules (rooms_crud, rooms_members, rooms_keys, rooms_theme)
import ``router`` from here so that routes are registered on a single APIRouter.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.chats.messages._router import epoch_micros
from app.chats.rooms.settings_backend import room_theme, room_view
from app.models_rooms import Room, RoomInviteEscrow, RoomMember, RoomRole
from app.peer.connection_manager import manager
from app.security.ecies_schema import EciesKeyFields

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/rooms", tags=["rooms"])


# Pydantic schemas


class EncryptedKeyPayload(EciesKeyFields):
    """ECIES-обёртка комнатного ключа (классика или post-quantum гибрид)."""


class RoomCreate(BaseModel):
    name: str = ""
    description: str = ""
    is_private: bool = False
    is_voice: bool = False  # True = voice channel (persistent, join/leave)

    # Client generates room_key(32 bytes) locally and encrypts with ECIES using its X25519 pubkey.
    # Server stores the encrypted blob — cannot decrypt without the client's private key.
    encrypted_room_key: EncryptedKeyPayload = Field(
        ..., description="room_key(32 bytes), encrypted with ECIES using the creator's X25519 public key"
    )
    # plaintext copy — used ONLY for is_private=False rooms so the
    # server can hand the key to new joiners without a round-trip to an
    # online member. Ignored for private rooms. If omitted on a public
    # room the server generates its own key server-side.
    public_room_key_hex: Optional[str] = Field(
        None, min_length=64, max_length=64, description="Plaintext 32-byte AES-256 room key (hex). Public rooms only."
    )


class ProvideKeyRequest(BaseModel):
    """Request to provide a key to a waiting member (from an online member)."""

    for_user_id: int = Field(..., description="user_id of the member who needs the key")
    ephemeral_pub: str = ""
    ciphertext: str = ""


class RoomUpdate(BaseModel):
    """Room settings update (owner/admin only)."""

    name: Optional[str] = None
    description: Optional[str] = None
    avatar_emoji: Optional[str] = None
    is_private: Optional[bool] = None
    auto_delete_seconds: Optional[int] = None  # None/0 = disabled, 30, 300, 3600, 86400
    slow_mode_seconds: Optional[int] = None  # 0 = disabled, 5, 15, 30, 60
    antispam_enabled: Optional[bool] = None
    antispam_config: Optional[str] = None  # JSON: {threshold, action, block_repeats, block_links}
    discussion_enabled: Optional[bool] = None  # Channel: enable comments under posts
    reactions_type: Optional[str] = None
    allowed_reactions: Optional[str] = None  # comma-separated emojis
    admin_signatures: Optional[bool] = None  # Show admin name under channel posts
    copy_protection: Optional[bool] = None  # Disable copy/forward in channel
    silent_default: Optional[bool] = None  # Posts silent by default
    join_approval: Optional[bool] = None  # Require approval to join
    hashtags_enabled: Optional[bool] = None  # Clickable hashtags


class ChangeRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|member)$")


class RoomThemeBody(BaseModel):
    wallpaper: Optional[str] = Field(None, max_length=255)
    accent: Optional[str] = None
    dark_mode: Optional[bool] = None


# Helper functions


def _room_dict(r: Room) -> dict:
    from app.chats.voice import get_voice_participants

    is_voice = bool(getattr(r, "is_voice", False))
    return room_view(
        id=r.id,
        name=r.name,
        member_count=r.member_count(),
        online_count=manager.count_online_from_set(r.member_user_ids()),
        created_at_us=epoch_micros(r.created_at),
        description=r.description,
        is_private=r.is_private,
        is_channel=r.is_channel,
        is_voice=is_voice,
        invite_code=r.invite_code,
        avatar_emoji=r.avatar_emoji,
        avatar_url=r.avatar_url,
        auto_delete_seconds=r.auto_delete_seconds,
        slow_mode_seconds=r.slow_mode_seconds,
        antispam_enabled=r.antispam_enabled,
        antispam_config=getattr(r, "antispam_config", None),
        creator_id=r.creator_id,
        theme_json=r.theme_json,
        discussion_enabled=getattr(r, "discussion_enabled", None),
        reactions_type=getattr(r, "reactions_type", None),
        allowed_reactions=getattr(r, "allowed_reactions", None),
        admin_signatures=getattr(r, "admin_signatures", None),
        copy_protection=getattr(r, "copy_protection", None),
        silent_default=getattr(r, "silent_default", None),
        join_approval=getattr(r, "join_approval", None),
        hashtags_enabled=getattr(r, "hashtags_enabled", None),
        replication_mode=getattr(r, "replication_mode", None),
        is_dm=getattr(r, "is_dm", None),
        voice_participants=get_voice_participants(r.id) if is_voice else None,
    )


def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not m:
        raise HTTPException(403, "You are not a member of this room")
    return m


def _approval_enforced(room) -> bool:
    """Энфорсится ли апрув для этой комнаты: per-room join_approval И глобальный
    Config-флаг (дефолт OFF — существующие join_approval=True не гейтятся до флипа)."""
    from app.config import Config

    return bool(getattr(room, "join_approval", False)) and bool(getattr(Config, "JOIN_APPROVAL_ENFORCED", False))


def _invalidate_room_escrows(room_id: int, db: Session) -> int:
    """Удаляет ВСЕ invite-escrow'ы комнаты при ротации room key (ADR-005 O4): escrow
    обёрнут на СТАРЫЙ ключ → устаревший escrow отдал бы вступающему мёртвый ключ.
    Отсутствующий escrow → вступающий падает в key_request. Вызывать ВЕЗДЕ, где
    рассылается key_rotated (rotate-key, kick, leave)."""
    return db.query(RoomInviteEscrow).filter(RoomInviteEscrow.room_id == room_id).delete()


def _can_admit(actor: RoomMember, room) -> bool:
    """Может ли actor ДОБАВИТЬ нового участника: ADMIN/OWNER — всегда; иначе только
    если апрув НЕ энфорсится (обычный член не должен обходить апрув). ЕДИНЫЙ предикат
    для provision-key и approve-join — без дрейфа между сайтами (ADR-005 O3)."""
    if actor.role in (RoomRole.ADMIN, RoomRole.OWNER):
        return True
    return not _approval_enforced(room)


async def _broadcast_key_request(
    room_id: int,
    for_user_id: int,
    for_pubkey: str,
    for_kyber_pubkey: str | None = None,
    for_kyber_sig: str | None = None,
) -> None:
    """
    Broadcasts a key re-encryption request to all online room members.
    Any member who has the room_key should encrypt it for the new member.
    Несёт аккаунтный Kyber-pub + подпись реквестера для гибридной PQ-обёртки:
    отвечающий проверяет подпись против припиненного Ed реквестера (клиент,
    resolvePeerKyberPub) — сам pub из broadcast НЕ доверенный.
    """
    payload = {
        "type": "key_request",
        "for_user_id": for_user_id,
        "for_pubkey": for_pubkey,
    }
    if for_kyber_pubkey and for_kyber_sig:
        payload["for_kyber_pubkey"] = for_kyber_pubkey
        payload["for_kyber_sig"] = for_kyber_sig
    await manager.broadcast_to_room(room_id, payload, exclude=for_user_id)


def _validate_theme(body: RoomThemeBody) -> str:
    """Validate and serialize theme to JSON string."""
    try:
        return room_theme(body.wallpaper, body.accent, body.dark_mode)
    except ValueError as refusal:
        raise HTTPException(400, str(refusal)) from refusal
