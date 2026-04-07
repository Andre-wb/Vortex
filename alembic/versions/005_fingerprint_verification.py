"""Add fingerprint verification columns to contacts table.

- contacts.fingerprint_verified:    whether the owner verified the contact's key
- contacts.fingerprint_verified_at: when verification happened
- contacts.fingerprint_pubkey_hash: SHA-256 of the pubkey at verification time
  (used to detect key changes and auto-invalidate verification)

Revision ID: 005_fingerprint_verification
Revises: 004_seed_phrase_hash
Create Date: 2026-04-02
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005_fingerprint_verification"
down_revision: Union[str, None] = "004_seed_phrase_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("contacts") as batch_op:
        batch_op.add_column(
            sa.Column("fingerprint_verified", sa.Boolean(), nullable=False, server_default="0"),
        )
        batch_op.add_column(
            sa.Column("fingerprint_verified_at", sa.DateTime(), nullable=True),
        )
        batch_op.add_column(
            sa.Column("fingerprint_pubkey_hash", sa.String(64), nullable=True),
        )


def downgrade() -> None:
    with op.batch_alter_table("contacts") as batch_op:
        batch_op.drop_column("fingerprint_pubkey_hash")
        batch_op.drop_column("fingerprint_verified_at")
        batch_op.drop_column("fingerprint_verified")
