"""O1: directed pre-provision комнатного ключа (offline-раздача, ADR-005).

Член с ключом провижнит room key для юзера X + добавляет X участником; X
забирает через key-bundle оффлайн. Гибрид/классика (EciesKeyFields), skip-if-
exists, self-heal (DELETE /my-key → has_key=False → key_request).
"""
import secrets

import pytest

from conftest import make_user, login_user, random_str


def _hybrid_key() -> dict:
    return {
        "hybrid":               True,
        "x25519_ephemeral_pub": secrets.token_hex(32),
        "kyber_ciphertext":     secrets.token_hex(1088),
        "ciphertext":           secrets.token_hex(60),
    }


def _classical_key() -> dict:
    return {"ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}


def _uid(u: dict) -> int:
    d = u.get("data", {})
    uid = d.get("user_id") or d.get("id")
    if not uid:
        pytest.skip("no user id")
    return uid


def _create_room_full(client, headers):
    r = client.post("/api/rooms", json={
        "name": f"room_{random_str(6)}", "is_private": True,
        "encrypted_room_key": _classical_key(),
    }, headers=headers)
    assert r.status_code in (200, 201), r.text
    b = r.json()
    room = b.get("room", b)
    return room.get("id") or b.get("id"), room.get("invite_code") or b.get("invite_code")


def _create_room(client, headers):
    return _create_room_full(client, headers)[0]


def _pair(client):
    """X зарегистрирован первым (для id/pubkey), A логинится последним (активен)."""
    x = make_user(client, suffix=f"x{random_str(6)}")
    a = make_user(client, suffix=f"a{random_str(6)}")
    a["headers"] = login_user(client, a["username"], a["password"])
    return a, x


def _provision(client, a, room_id, x_id, key):
    return client.post(f"/api/rooms/{room_id}/provision-key",
                       json={"for_user_id": x_id, **key}, headers=a["headers"])


def test_provision_hybrid_and_fetch_offline(client):
    a, x = _pair(client)
    x_id = _uid(x)
    room_id = _create_room(client, a["headers"])
    key = _hybrid_key()

    r = _provision(client, a, room_id, x_id, key)
    assert r.status_code == 200, r.text
    assert r.json()["added"] is True

    # X (не онлайн во время провижна) забирает ключ через key-bundle
    x_h = login_user(client, x["username"], x["password"])
    got = client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h).json()
    assert got["has_key"] is True
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == key["kyber_ciphertext"]
    assert got["x25519_ephemeral_pub"] == key["x25519_ephemeral_pub"]


def test_provision_classical_works(client):
    a, x = _pair(client)
    x_id = _uid(x)
    room_id = _create_room(client, a["headers"])
    key = _classical_key()
    assert _provision(client, a, room_id, x_id, key).status_code == 200

    x_h = login_user(client, x["username"], x["password"])
    got = client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h).json()
    assert got["has_key"] is True
    assert got["ephemeral_pub"] == key["ephemeral_pub"]
    assert "kyber_ciphertext" not in got


def test_provision_skip_if_exists(client):
    a, x = _pair(client)
    x_id = _uid(x)
    room_id = _create_room(client, a["headers"])
    first = _classical_key()
    assert _provision(client, a, room_id, x_id, first).status_code == 200
    # Повторный провижн не перетирает рабочий ключ X
    r2 = _provision(client, a, room_id, x_id, _hybrid_key())
    assert r2.status_code == 200
    assert r2.json().get("already_has_key") is True

    x_h = login_user(client, x["username"], x["password"])
    got = client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h).json()
    assert got["ephemeral_pub"] == first["ephemeral_pub"]   # остался первый


def test_provision_requires_caller_membership(client):
    a, x = _pair(client)
    x_id = _uid(x)
    room_id = _create_room(client, a["headers"])
    # X (не член, без ключа) не может провижнить
    x_h = login_user(client, x["username"], x["password"])
    r = client.post(f"/api/rooms/{room_id}/provision-key",
                    json={"for_user_id": _uid(a), **_classical_key()}, headers=x_h)
    assert r.status_code in (403, 404), r.text


def test_keybundle_no_500_when_pending_reread(client):
    """Live-верификация фикса is_expired: keyless-член дважды дёргает key-bundle;
    второй раз get_key_bundle пере-читает PendingKeyRequest (naive из SQLite) и
    проверяет is_expired — раньше это был 500 (offset-naive vs aware) ровно на
    offline-join пути, ради которого O1 и существует."""
    a, x = _pair(client)
    room_id, invite = _create_room_full(client, a["headers"])
    if not invite:
        pytest.skip("no invite_code in create response")
    x_h = login_user(client, x["username"], x["password"])
    # X вступает по коду → член без ключа, создаётся PendingKeyRequest
    jr = client.post(f"/api/rooms/join/{invite}", headers=x_h)
    assert jr.status_code in (200, 201), jr.text
    # Первый key-bundle: has_key=False, создаёт pending
    r1 = client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h)
    assert r1.status_code == 200, r1.text
    assert r1.json()["has_key"] is False
    # Второй: пере-читает pending + is_expired — НЕ 500
    r2 = client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h)
    assert r2.status_code == 200, r2.text
    assert r2.json()["has_key"] is False


def test_provision_requires_caller_has_key(client):
    """Член БЕЗ ключа не может провижнить (403)."""
    a, x = _pair(client)
    room_id, invite = _create_room_full(client, a["headers"])
    if not invite:
        pytest.skip("no invite_code")
    # B вступает по коду → член без ключа
    b = make_user(client, suffix=f"b{random_str(6)}")
    b_h = login_user(client, b["username"], b["password"])
    client.post(f"/api/rooms/join/{invite}", headers=b_h)
    # B (член, но без ключа) пробует провижнить для X → 403
    r = client.post(f"/api/rooms/{room_id}/provision-key",
                    json={"for_user_id": _uid(x), **_classical_key()}, headers=b_h)
    assert r.status_code == 403, r.text


def test_provision_rejects_banned_target(client):
    """Забаненный target → 403 (нельзя провижнить кикнутому)."""
    a, x = _pair(client)
    x_id = _uid(x)
    room_id = _create_room(client, a["headers"])
    # X добавлен провижном → член
    assert _provision(client, a, room_id, x_id, _classical_key()).status_code == 200
    # A банит X
    ban = client.put(f"/api/rooms/{room_id}/members/{x_id}/ban", headers=a["headers"])
    if ban.status_code != 200:
        pytest.skip(f"ban endpoint unavailable: {ban.status_code}")
    # Повторный провижн для забаненного → 403
    r = _provision(client, a, room_id, x_id, _classical_key())
    assert r.status_code == 403, r.text


def test_self_heal_forget_my_key(client):
    a, x = _pair(client)
    x_id = _uid(x)
    room_id = _create_room(client, a["headers"])
    _provision(client, a, room_id, x_id, _classical_key())

    x_h = login_user(client, x["username"], x["password"])
    assert client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h).json()["has_key"] is True

    # Self-heal: X удаляет негодный ключ → key-bundle снова has_key=False (→ key_request)
    d = client.delete(f"/api/rooms/{room_id}/my-key", headers=x_h)
    assert d.status_code == 200, d.text
    assert d.json()["deleted"] is True
    got = client.get(f"/api/rooms/{room_id}/key-bundle", headers=x_h).json()
    assert got["has_key"] is False
