"""Add federated_rooms persistence table.

Revision ID: 002_federated_rooms
Revises: 001_initial
Create Date: 2026-03-29
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_federated_rooms"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "federated_rooms",
        sa.Column("id",             sa.Integer(),      nullable=False, autoincrement=True),
        sa.Column("virtual_id",     sa.Integer(),      nullable=False),
        sa.Column("peer_ip",        sa.String(128),    nullable=False),
        sa.Column("peer_port",      sa.Integer(),      nullable=False),
        sa.Column("remote_room_id", sa.Integer(),      nullable=False),
        sa.Column("remote_jwt",     sa.Text(),         nullable=False, server_default=""),
        sa.Column("room_name",      sa.String(255),    nullable=False),
        sa.Column("invite_code",    sa.String(32),     nullable=False),
        sa.Column("is_private",     sa.Boolean(),      nullable=True),
        sa.Column("member_count",   sa.Integer(),      nullable=True),
        sa.Column("created_at",     sa.DateTime(),     nullable=True),
        sa.Column("last_accessed",  sa.DateTime(),     nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("virtual_id"),
    )
    op.create_index("ix_federated_rooms_virtual_id", "federated_rooms", ["virtual_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_federated_rooms_virtual_id", table_name="federated_rooms")
    op.drop_table("federated_rooms")
