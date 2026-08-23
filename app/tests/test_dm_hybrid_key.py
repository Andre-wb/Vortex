"""Post-quantum гибрид (X25519 + ML-KEM-768) в DM-пути обёртки ключа.

Проверяем, что kyber_ciphertext переживает store→fetch и не теряется схемами:
  - гибридный конверт сохраняется при создании DM и возвращается через key-bundle
    в гибридной форме (hybrid/x25519_ephemeral_pub/kyber_ciphertext);
  - классический конверт по-прежнему работает (backward-compat) и не тащит
    гибридных полей;
  - Pydantic-валидатор отвергает битые формы.
"""

import secrets

import pytest
from conftest import login_user, make_user, random_str


def _target_id(u: dict) -> int:
    data = u.get("data", {})
    uid = data.get("user_id") or data.get("id")
    if not uid:
        pytest.skip("Cannot determine target user id from register response")
    return uid


def _make_pair(client):
    """Регистрирует получателя и отправителя; логинит отправителя последним."""
    target = make_user(client, suffix=f"t{random_str(6)}")
    sender = make_user(client, suffix=f"s{random_str(6)}")
    sender["headers"] = login_user(client, sender["username"], sender["password"])
    return sender, target


def test_dm_other_user_carries_kyber_pub_sig(client):
    """create-DM other_user отдаёт kyber_public_key + kyber_public_key_sig —
    канал capability+аутентичности для гибрид-отправки (K4c)."""
    target = make_user(client, suffix=f"t{random_str(6)}")
    # target публикует свой аккаунтный Kyber-pub + подпись (K2-эндпоинт)
    t_headers = login_user(client, target["username"], target["password"])
    pub = secrets.token_hex(1184)
    sig = secrets.token_hex(64)
    r = client.post("/api/keys/kyber", json={"kyber_public_key": pub, "kyber_public_key_sig": sig}, headers=t_headers)
    assert r.status_code == 200, r.text

    sender = make_user(client, suffix=f"s{random_str(6)}")
    sender["headers"] = login_user(client, sender["username"], sender["password"])
    resp = client.post(f"/api/dm/{_target_id(target)}", json={}, headers=sender["headers"])
    assert resp.status_code == 200, resp.text
    other = resp.json()["other_user"]
    assert other["kyber_public_key"] == pub
    assert other["kyber_public_key_sig"] == sig


def _hybrid_key() -> dict:
    return {
        "hybrid": True,
        "x25519_ephemeral_pub": secrets.token_hex(32),  # 64 hex
        "kyber_ciphertext": secrets.token_hex(1088),  # ML-KEM-768 ct = 2176 hex
        "ciphertext": secrets.token_hex(60),  # 120 hex
    }


def _classical_key() -> dict:
    return {
        "ephemeral_pub": secrets.token_hex(32),
        "ciphertext": secrets.token_hex(60),
    }


def _create_dm(client, sender, target_id, own_key):
    r = client.post(f"/api/dm/{target_id}", json={"encrypted_room_key": own_key}, headers=sender["headers"])
    assert r.status_code == 200, r.text
    return r.json()["room"]["id"]


def _fetch_key(client, sender, room_id):
    r = client.get(f"/api/rooms/{room_id}/key-bundle", headers=sender["headers"])
    assert r.status_code == 200, r.text
    return r.json()


def test_hybrid_key_survives_store_fetch(client):
    sender, target = _make_pair(client)
    key = _hybrid_key()
    room_id = _create_dm(client, sender, _target_id(target), key)

    got = _fetch_key(client, sender, room_id)
    assert got["has_key"] is True
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == key["kyber_ciphertext"]
    assert got["x25519_ephemeral_pub"] == key["x25519_ephemeral_pub"]
    assert got["ciphertext"] == key["ciphertext"]
    assert "ephemeral_pub" not in got  # гибрид отдаёт X25519-эфемерный под своим именем


def test_hybrid_key_for_recipient_survives(client):
    """Направление ради которого K4a: отправитель кладёт гибрид для ПОЛУЧАТЕЛЯ
    (ветка encrypted_key_for_target), получатель забирает свой key-bundle."""
    sender, target = _make_pair(client)
    key = _hybrid_key()
    r = client.post(f"/api/dm/{_target_id(target)}", json={"encrypted_key_for_target": key}, headers=sender["headers"])
    assert r.status_code == 200, r.text
    room_id = r.json()["room"]["id"]

    # Переключаем сессию на получателя и читаем ЕГО ключ
    target["headers"] = login_user(client, target["username"], target["password"])
    got = _fetch_key(client, target, room_id)
    assert got["has_key"] is True
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == key["kyber_ciphertext"]
    assert got["x25519_ephemeral_pub"] == key["x25519_ephemeral_pub"]
    assert got["ciphertext"] == key["ciphertext"]


def test_classical_key_still_works(client):
    sender, target = _make_pair(client)
    key = _classical_key()
    room_id = _create_dm(client, sender, _target_id(target), key)

    got = _fetch_key(client, sender, room_id)
    assert got["has_key"] is True
    assert got["ephemeral_pub"] == key["ephemeral_pub"]
    assert got["ciphertext"] == key["ciphertext"]
    assert "kyber_ciphertext" not in got
    assert "hybrid" not in got


def test_schema_rejects_hybrid_without_kyber_ciphertext(client):
    sender, target = _make_pair(client)
    bad = {"hybrid": True, "x25519_ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}
    r = client.post(f"/api/dm/{_target_id(target)}", json={"encrypted_room_key": bad}, headers=sender["headers"])
    assert r.status_code in (400, 422), r.text
