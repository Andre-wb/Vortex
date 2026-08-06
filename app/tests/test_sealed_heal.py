"""Heal-миграция после удаления сломанного sealed-prekey пути.

Отравленные `EncryptedRoomKey` — те, что старый consumer скопировал ДОСЛОВНО из
`sealed_key_packages` (ephemeral_pub+ciphertext). Heal матчит ровно эти строки
через JOIN (случайные ephemeral+nonce не коллизят с легит-обёрткой → ноль
false-positive, независимо от recipient_pub/escrow). Легит-ключи не трогает.
"""

from sqlalchemy import create_engine, text

# Точная SQL heal-миграции (app/database.py) — фиксируем поведение.
_HEAL = (
    "DELETE FROM encrypted_room_keys WHERE id IN ("
    " SELECT erk.id FROM encrypted_room_keys erk"
    " JOIN sealed_key_packages skp"
    " ON skp.room_id = erk.room_id"
    " AND skp.ephemeral_pub = erk.ephemeral_pub"
    " AND skp.ciphertext = erk.ciphertext)"
)


def _make_db(path):
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE encrypted_room_keys ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, user_id INTEGER,"
                " ephemeral_pub TEXT, ciphertext TEXT, recipient_pub TEXT)"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE sealed_key_packages ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER,"
                " ephemeral_pub TEXT, ciphertext TEXT)"
            )
        )
        # sealed-пакет, который был claimed → скопирован в EncryptedRoomKey
        conn.execute(
            text("INSERT INTO sealed_key_packages (room_id, ephemeral_pub, ciphertext) VALUES (10, 'seal_e', 'seal_c')")
        )
        conn.execute(
            text(
                "INSERT INTO encrypted_room_keys (room_id, user_id, ephemeral_pub, ciphertext, recipient_pub) VALUES"
                " (10, 2, 'seal_e', 'seal_c', 'ZZ'),"  # отравлено: дословная копия sealed-пакета
                " (10, 1, 'legit_e', 'legit_c', 'AA'),"  # легит: не матчит ни один sealed
                " (11, 3, 'seal_e', 'seal_c', 'BB')"  # тот же ephemeral, но ДРУГАЯ комната → не матчит
            )
        )
    return engine


def _rows(conn):
    return {(r[0], r[1]) for r in conn.execute(text("SELECT room_id, user_id FROM encrypted_room_keys")).fetchall()}


def test_heal_removes_only_sealed_copies(tmp_path):
    engine = _make_db(tmp_path / "heal.db")
    with engine.begin() as conn:
        conn.execute(text(_HEAL))
    with engine.connect() as conn:
        rows = _rows(conn)
    assert (10, 2) not in rows  # отравленная копия удалена
    assert (10, 1) in rows  # легит цел
    assert (11, 3) in rows  # совпадение ephemeral в другой комнате не тронуто


def test_heal_idempotent(tmp_path):
    engine = _make_db(tmp_path / "heal2.db")
    with engine.begin() as conn:
        conn.execute(text(_HEAL))
        conn.execute(text(_HEAL))
    with engine.connect() as conn:
        assert len(_rows(conn)) == 2
