"""K5-миграция: обнуление легаси серверных Kyber-pub.

Старая серверная keygen (убрана в K2) оставляла kyber_public_key с потерянным
приватным → мусор. Client-publish (/api/keys/kyber) ставит И pub, И sig, поэтому
легаси распознаётся как pub без sig. Обнуляем ровно их; подписанные (client-
published) и пустые не трогаем.
"""
from sqlalchemy import create_engine, text

# Точная SQL K5-миграции (app/database.py).
_NULL_LEGACY = (
    "UPDATE users SET kyber_public_key = NULL "
    "WHERE kyber_public_key IS NOT NULL AND kyber_public_key_sig IS NULL"
)


def _make_db(path):
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " kyber_public_key TEXT, kyber_public_key_sig TEXT)"
        ))
        conn.execute(text(
            "INSERT INTO users (id, kyber_public_key, kyber_public_key_sig) VALUES"
            " (1, 'LEGACY_GARBAGE', NULL),"    # легаси: pub без sig → обнулить
            " (2, 'CLIENT_PUB', 'CLIENT_SIG')," # client-published: pub+sig → сохранить
            " (3, NULL, NULL)"                  # нет Kyber → не трогать
        ))
    return engine


def _kyber(conn):
    return {r[0]: r[1] for r in conn.execute(
        text("SELECT id, kyber_public_key FROM users")).fetchall()}


def test_nulls_only_unsigned_legacy(tmp_path):
    engine = _make_db(tmp_path / "kyber.db")
    with engine.begin() as conn:
        conn.execute(text(_NULL_LEGACY))
    with engine.connect() as conn:
        k = _kyber(conn)
    assert k[1] is None            # легаси-мусор обнулён
    assert k[2] == "CLIENT_PUB"    # client-published сохранён
    assert k[3] is None            # пустой не тронут


def test_idempotent(tmp_path):
    engine = _make_db(tmp_path / "kyber2.db")
    with engine.begin() as conn:
        conn.execute(text(_NULL_LEGACY))
        conn.execute(text(_NULL_LEGACY))
    with engine.connect() as conn:
        assert _kyber(conn)[2] == "CLIENT_PUB"
