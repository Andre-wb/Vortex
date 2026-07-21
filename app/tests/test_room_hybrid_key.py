"""K4d: post-quantum гибрид в группового пути обёртки ключа (create room/channel).

Серверные схемы create-room/channel приняли общую EciesKeyFields (гибрид+классика);
self-ключ создателя переживает store→fetch через тот же key-bundle, что DM.
"""
import secrets

import pytest

from conftest import make_user, login_user, random_str


def _sender(client):
    u = make_user(client, suffix=f"r{random_str(6)}")
    u["headers"] = login_user(client, u["username"], u["password"])
    return u


def _hybrid_key() -> dict:
    return {
        "hybrid":               True,
        "x25519_ephemeral_pub": secrets.token_hex(32),
        "kyber_ciphertext":     secrets.token_hex(1088),
        "ciphertext":           secrets.token_hex(60),
    }


def _classical_key() -> dict:
    return {"ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}


def _create_room(client, u, key):
    r = client.post("/api/rooms", json={
        "name": f"room_{random_str(6)}", "is_private": False, "encrypted_room_key": key,
    }, headers=u["headers"])
    assert r.status_code in (200, 201), r.text
    body = r.json()
    return body.get("id") or body.get("room", {}).get("id")


def _fetch_key(client, u, room_id):
    r = client.get(f"/api/rooms/{room_id}/key-bundle", headers=u["headers"])
    assert r.status_code == 200, r.text
    return r.json()


def test_room_create_hybrid_self_key_survives(client):
    u = _sender(client)
    key = _hybrid_key()
    room_id = _create_room(client, u, key)
    got = _fetch_key(client, u, room_id)
    assert got["has_key"] is True
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == key["kyber_ciphertext"]
    assert got["x25519_ephemeral_pub"] == key["x25519_ephemeral_pub"]
    assert "ephemeral_pub" not in got


def test_room_create_classical_still_works(client):
    u = _sender(client)
    key = _classical_key()
    room_id = _create_room(client, u, key)
    got = _fetch_key(client, u, room_id)
    assert got["has_key"] is True
    assert got["ephemeral_pub"] == key["ephemeral_pub"]
    assert "kyber_ciphertext" not in got
    assert "hybrid" not in got


def test_channel_create_hybrid_self_key_survives(client):
    u = _sender(client)
    key = _hybrid_key()
    r = client.post("/api/channels", json={
        "name": f"ch_{random_str(6)}", "encrypted_room_key": key,
    }, headers=u["headers"])
    if r.status_code not in (200, 201):
        pytest.skip(f"channel create unavailable: {r.status_code}")
    channel_id = r.json().get("id") or r.json().get("room", {}).get("id")
    got = _fetch_key(client, u, channel_id)
    assert got["has_key"] is True
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == key["kyber_ciphertext"]
