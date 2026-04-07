"""Phone nullable + IP privacy columns.

- users.phone: NOT NULL → nullable (anonymous registration without phone)
- users.last_ip, user_devices.ip_address, refresh_tokens.ip_address:
  default changed to NULL (IP storage now optional via STORE_IPS config)

Revision ID: 003_phone_nullable_ip_privacy
Revises: 002_federated_rooms
Create Date: 2026-04-02
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_phone_nullable_ip_privacy"
down_revision: Union[str, None] = "002_federated_rooms"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Phone: NOT NULL → nullable (username-only registration)
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "phone",
            existing_type=sa.String(20),
            nullable=True,
        )


def downgrade() -> None:
    # Revert phone to NOT NULL (will fail if NULLs exist — intentional)
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "phone",
            existing_type=sa.String(20),
            nullable=False,
        )
