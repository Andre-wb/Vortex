#!/usr/bin/env python3
"""Разворачивает схему Vortex в базе Postgres — вход для `cargo sqlx prepare`.

Источник истины схемы в проекте — модели SQLAlchemy (`app.base.Base.metadata`),
а не alembic: каталог `alembic/versions/` пуст, поэтому `init_db()` создаёт
таблицы через `create_all`. Компилятору `sqlx` нужна живая база с этой схемой,
и этот скрипт её материализует.

Запуск (из корня репозитория):
    createdb vortex_sqlx
    python scripts/pg_schema_for_sqlx.py postgresql://localhost:5432/vortex_sqlx

Затем, из корня репозитория:
    DATABASE_URL=postgres://localhost:5432/vortex_sqlx cargo sqlx prepare --workspace -- --all-targets

Скрипт только добавляет отсутствующие таблицы (`create_all`) и ничего не удаляет,
но целевая база всё равно должна быть отдельной: в неё пишут тесты
`cargo test -p vortex-storage`.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)

    url = sys.argv[1]
    if not url.startswith("postgresql://") and not url.startswith("postgresql+"):
        print(f"нужен postgresql:// URL, получено: {url}")
        raise SystemExit(2)

    os.environ["DATABASE_URL"] = url
    os.environ.setdefault("JWT_SECRET", "schema_only_secret_minimum_32_chars_1234")
    os.environ.setdefault("CSRF_SECRET", "schema_only_secret_minimum_32_chars_1234")
    os.environ.setdefault("NODE_INITIALIZED", "true")
    sys.path.insert(0, ROOT)

    from app.base import Base
    from app.database import engine

    Base.metadata.create_all(bind=engine)
    print(f"{engine.url}: {len(Base.metadata.tables)} таблиц")


if __name__ == "__main__":
    main()
