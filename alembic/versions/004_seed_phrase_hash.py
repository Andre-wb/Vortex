"""Add seed_phrase_hash column for BIP39 anonymous recovery.

- users.seed_phrase_hash: Argon2id hash of 24-word BIP39 mnemonic
  (NULL for users who registered with phone number)

Revision ID: 004_seed_phrase_hash
Revises: 003_phone_nullable_ip_privacy
Create Date: 2026-04-02
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004_seed_phrase_hash"
down_revision: Union[str, None] = "003_phone_nullable_ip_privacy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("seed_phrase_hash", sa.String(512), nullable=True),
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("seed_phrase_hash")
