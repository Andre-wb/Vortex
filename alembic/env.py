"""
Alembic environment configuration for Vortex Chat.

Reads database URL from app.config.Config and uses the same Base metadata
as the application, enabling autogenerate to detect model changes.

Supports both SQLite and PostgreSQL backends.
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.base import Base  # noqa: E402
from app.config import Config  # noqa: E402

# Import all models so Base.metadata is fully populated
import app.models  # noqa: E402, F401
import app.models_rooms  # noqa: E402, F401
from app.models import contact as _contact  # noqa: E402, F401

# Alembic Config object
config = context.config

# Setup logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata

# ---------------------------------------------------------------------------
# Resolve database URL — prefer DATABASE_URL / POSTGRES_*, fallback to SQLite
# ---------------------------------------------------------------------------
_db_url = Config.get_database_url()

# Ensure sync driver for Alembic (replace asyncpg with psycopg2)
if "postgresql+asyncpg" in _db_url:
    _db_url = _db_url.replace("postgresql+asyncpg", "postgresql+psycopg2", 1)
elif _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

config.set_main_option("sqlalchemy.url", _db_url)

_is_sqlite = _db_url.startswith("sqlite://")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Generates SQL script without connecting to the database.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=_is_sqlite,  # Required for SQLite ALTER TABLE
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an engine and connects to the database.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=_is_sqlite,  # Required for SQLite ALTER TABLE
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
