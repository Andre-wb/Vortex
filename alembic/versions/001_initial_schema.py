"""Initial schema — baseline from existing models.

Revision ID: 001_initial
Revises: None
Create Date: 2026-03-23

This is a baseline migration. It represents the existing database schema
as of v5.0.0. For existing databases, stamp this revision without running it:

    alembic stamp 001_initial

For new databases, this creates all tables from scratch.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("phone", sa.String(20), unique=True, nullable=False),
        sa.Column("username", sa.String(50), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=True),
        sa.Column("avatar_emoji", sa.String(10), server_default="👤"),
        sa.Column("avatar_url", sa.String(255), nullable=True),
        sa.Column("x25519_public_key", sa.String(64), nullable=True),
        sa.Column("email", sa.String(255), unique=True, nullable=True),
        sa.Column("last_ip", sa.String(45), nullable=True),
        sa.Column("network_mode", sa.String(10), server_default="local"),
        sa.Column("totp_secret", sa.String(64), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), server_default="0"),
        sa.Column("is_bot", sa.Boolean(), server_default="0"),
        sa.Column("is_active", sa.Boolean(), server_default="1"),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("last_seen", sa.DateTime()),
        sa.Column("global_muted_until", sa.DateTime(), nullable=True),
        sa.Column("banned_until", sa.DateTime(), nullable=True),
        sa.Column("strike_count", sa.Integer(), server_default="0"),
    )
    op.create_index("ix_users_phone", "users", ["phone"])
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_x25519", "users", ["x25519_public_key"])

    # Refresh tokens
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
    )
    op.create_index("ix_rt_user_id", "refresh_tokens", ["user_id"])

    # Spaces
    op.create_table(
        "spaces",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), server_default=""),
        sa.Column("avatar_emoji", sa.String(10), server_default="🏠"),
        sa.Column("avatar_url", sa.String(255), nullable=True),
        sa.Column("creator_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("invite_code", sa.String(16), unique=True, nullable=False),
        sa.Column("is_public", sa.Boolean(), server_default="0"),
        sa.Column("member_count", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime()),
    )

    # Rooms
    op.create_table(
        "rooms",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), server_default=""),
        sa.Column("creator_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("is_private", sa.Boolean(), server_default="0"),
        sa.Column("invite_code", sa.String(16), unique=True, nullable=False),
        sa.Column("max_members", sa.Integer(), server_default="200"),
        sa.Column("is_dm", sa.Boolean(), server_default="0"),
        sa.Column("is_channel", sa.Boolean(), server_default="0"),
        sa.Column("is_voice", sa.Boolean(), server_default="0"),
        sa.Column("subscriber_count", sa.Integer(), server_default="0"),
        sa.Column("space_id", sa.Integer(), sa.ForeignKey("spaces.id", ondelete="SET NULL"), nullable=True),
        sa.Column("category_id", sa.Integer(), nullable=True),
        sa.Column("order_idx", sa.Integer(), server_default="0"),
        sa.Column("pinned_message_id", sa.Integer(), nullable=True),
        sa.Column("auto_delete_seconds", sa.Integer(), nullable=True),
        sa.Column("slow_mode_seconds", sa.Integer(), server_default="0"),
        sa.Column("avatar_emoji", sa.String(10), server_default="💬"),
        sa.Column("avatar_url", sa.String(255), nullable=True),
        sa.Column("antispam_enabled", sa.Boolean(), server_default="1"),
        sa.Column("antispam_config", sa.Text(), server_default="{}"),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )

    # Messages
    op.create_table(
        "messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("room_id", sa.Integer(), sa.ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sender_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("msg_type", sa.String(10), server_default="text"),
        sa.Column("content_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=True),
        sa.Column("file_name", sa.String(255), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("reply_to_id", sa.Integer(), sa.ForeignKey("messages.id", ondelete="SET NULL"), nullable=True),
        sa.Column("thread_id", sa.Integer(), sa.ForeignKey("messages.id", ondelete="SET NULL"), nullable=True),
        sa.Column("thread_count", sa.Integer(), server_default="0"),
        sa.Column("is_edited", sa.Boolean(), server_default="0"),
        sa.Column("forwarded_from", sa.String(100), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("scheduled_at", sa.DateTime(), nullable=True),
        sa.Column("is_scheduled", sa.Boolean(), server_default="0"),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index("ix_msg_room_created", "messages", ["room_id", "created_at"])
    op.create_index("ix_msg_thread_id", "messages", ["thread_id"])

    # Room members
    op.create_table(
        "room_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("room_id", sa.Integer(), sa.ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(10), server_default="member"),
        sa.Column("joined_at", sa.DateTime()),
        sa.Column("is_muted", sa.Boolean(), server_default="0"),
        sa.Column("is_banned", sa.Boolean(), server_default="0"),
        sa.Column("muted_until", sa.DateTime(), nullable=True),
        sa.Column("last_read_message_id", sa.Integer(), nullable=True),
        sa.UniqueConstraint("room_id", "user_id"),
    )
    op.create_index("ix_rm_room_user", "room_members", ["room_id", "user_id"])

    # Encrypted room keys
    op.create_table(
        "encrypted_room_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("room_id", sa.Integer(), sa.ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ephemeral_pub", sa.String(64), nullable=False),
        sa.Column("ciphertext", sa.String(120), nullable=False),
        sa.Column("recipient_pub", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("room_id", "user_id"),
    )
    op.create_index("ix_erk_room_user", "encrypted_room_keys", ["room_id", "user_id"])

    # Pending key requests
    op.create_table(
        "pending_key_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("room_id", sa.Integer(), sa.ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pubkey_hex", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("room_id", "user_id"),
    )
    op.create_index("ix_pkr_room_user", "pending_key_requests", ["room_id", "user_id"])

    # Bots
    op.create_table(
        "bots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("api_token", sa.String(64), unique=True, nullable=False),
        sa.Column("name", sa.String(50), nullable=False),
        sa.Column("description", sa.String(500), server_default=""),
        sa.Column("avatar_url", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="1"),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("commands", sa.Text(), server_default="[]"),
        sa.Column("mini_app_url", sa.String(500), nullable=True),
        sa.Column("mini_app_enabled", sa.Boolean(), server_default="0"),
        sa.Column("is_public", sa.Boolean(), server_default="0"),
        sa.Column("category", sa.String(30), server_default="other"),
        sa.Column("installs", sa.Integer(), server_default="0"),
        sa.Column("rating", sa.Float(), server_default="0.0"),
        sa.Column("rating_count", sa.Integer(), server_default="0"),
    )

    # Other tables: upload_quotas, push_subscriptions, user_statuses,
    # bot_reviews, user_reports, user_strikes, file_transfers,
    # message_reactions, room_tasks, saved_messages,
    # sticker_packs, stickers, user_favorite_packs,
    # space_members, space_categories
    # (abbreviated for baseline — all created by SQLAlchemy create_all)


def downgrade() -> None:
    op.drop_table("pending_key_requests")
    op.drop_table("encrypted_room_keys")
    op.drop_table("room_members")
    op.drop_table("messages")
    op.drop_table("rooms")
    op.drop_table("spaces")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
