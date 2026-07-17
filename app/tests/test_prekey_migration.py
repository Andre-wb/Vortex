"""Тест SQLite-миграции prekey_bundles: rebuild снимает UNIQUE(user_id) и
добавляет device_id, сохраняя данные. Основной набор идёт в in-memory БД со
свежей схемой из модели, поэтому rebuild там не срабатывает — этот тест
проверяет rebuild против настоящей legacy-таблицы (inline UNIQUE(user_id)) во
временном файле.
"""

import pytest
from sqlalchemy import create_engine, text

from app.database import _rebuild_prekey_bundles_if_legacy


_LEGACY_PREKEY_BUNDLES = (
    "CREATE TABLE prekey_bundles ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,"
    " identity_key BLOB NOT NULL, signed_prekey BLOB NOT NULL,"
    " signed_prekey_sig BLOB NOT NULL, signed_prekey_id INTEGER NOT NULL DEFAULT 0,"
    " identity_key_ed BLOB, identity_key_sig BLOB, supports_v2 BOOLEAN,"
    " created_at DATETIME, updated_at DATETIME)"
)


def _make_legacy_db(path) -> object:
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT)"))
        conn.execute(text("CREATE TABLE user_devices (id INTEGER PRIMARY KEY AUTOINCREMENT)"))
        conn.execute(text(_LEGACY_PREKEY_BUNDLES))
        conn.execute(text("INSERT INTO users (id) VALUES (1), (2)"))
        conn.execute(text(
            "INSERT INTO prekey_bundles"
            " (user_id, identity_key, signed_prekey, signed_prekey_sig, signed_prekey_id,"
            "  identity_key_ed, identity_key_sig, supports_v2, created_at, updated_at)"
            " VALUES"
            " (1, X'aa', X'bb', X'cc', 1, X'dd', X'ee', 1, '2026-01-01', '2026-01-01'),"
            " (2, X'a1', X'b1', X'c1', 1, NULL, NULL, NULL, '2026-01-02', '2026-01-02')"
        ))
    return engine


def _columns(conn) -> list:
    return [row[1] for row in conn.execute(text("PRAGMA table_info(prekey_bundles)")).fetchall()]


def test_rebuild_adds_device_id_and_preserves_rows(tmp_path):
    engine = _make_legacy_db(tmp_path / "legacy.db")
    with engine.begin() as conn:
        assert "device_id" not in _columns(conn)
        _rebuild_prekey_bundles_if_legacy(conn)
        cols = _columns(conn)
        assert "device_id" in cols
        # Данные сохранены (2 строки), device_id заполнен NULL
        rows = conn.execute(text(
            "SELECT user_id, device_id, supports_v2 FROM prekey_bundles ORDER BY user_id"
        )).fetchall()
        assert [(r[0], r[1]) for r in rows] == [(1, None), (2, None)]
        assert rows[0][2] == 1  # supports_v2 первой строки перенесён


def test_rebuild_drops_user_unique(tmp_path):
    """После rebuild у одного user_id можно завести два устройства."""
    engine = _make_legacy_db(tmp_path / "legacy.db")
    with engine.begin() as conn:
        _rebuild_prekey_bundles_if_legacy(conn)
        # user_id=1 уже имеет строку с device_id=NULL; добавляем device_id=10 — ок
        conn.execute(text(
            "INSERT INTO prekey_bundles"
            " (user_id, device_id, identity_key, signed_prekey, signed_prekey_sig,"
            "  signed_prekey_id, created_at, updated_at)"
            " VALUES (1, 10, X'0a', X'0b', X'0c', 1, '2026-01-03', '2026-01-03')"
        ))
        cnt = conn.execute(text("SELECT COUNT(*) FROM prekey_bundles WHERE user_id=1")).scalar()
        assert cnt == 2


def test_rebuild_is_idempotent(tmp_path):
    engine = _make_legacy_db(tmp_path / "legacy.db")
    with engine.begin() as conn:
        _rebuild_prekey_bundles_if_legacy(conn)
        cols_after_first = _columns(conn)
        # Второй вызов — no-op (device_id уже есть), без ошибок и без осиротевшей _new
        _rebuild_prekey_bundles_if_legacy(conn)
        assert _columns(conn) == cols_after_first
        orphan = conn.execute(text(
            "SELECT 1 FROM sqlite_master WHERE name='prekey_bundles_new'"
        )).fetchone()
        assert orphan is None


def test_rebuild_noop_when_table_absent(tmp_path):
    """Нет таблицы prekey_bundles — rebuild ничего не делает (создастся моделью)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    with engine.begin() as conn:
        _rebuild_prekey_bundles_if_legacy(conn)  # не должно бросить
        assert conn.execute(text(
            "SELECT 1 FROM sqlite_master WHERE name='prekey_bundles'"
        )).fetchone() is None
