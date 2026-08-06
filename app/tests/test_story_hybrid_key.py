"""K4e: post-quantum гибрид в story-envelope хранилище.

StoryKeyEnvelope.kyber_ciphertext переживает store→fetch; _story_dict отдаёт
гибрид-форму при наличии kyber, иначе классику (backward-compat).
"""
import json
import secrets

from conftest import login_user, make_user


def _hybrid_env(uid: int) -> dict:
    return {
        "user_id":              uid,
        "hybrid":               True,
        "x25519_ephemeral_pub": secrets.token_hex(32),
        "kyber_ciphertext":     secrets.token_hex(1088),
        "ciphertext":           secrets.token_hex(60),
    }


def _classical_env(uid: int) -> dict:
    return {"user_id": uid, "ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}


def _create_story(client, headers, envelopes):
    data = {
        "media_type":    "text",
        "text_ct":       b"hi".hex(),
        "meta_ct":       json.dumps({}).encode().hex(),
        "duration":      "5",
        "key_envelopes": json.dumps(envelopes),
    }
    r = client.post("/api/stories", data=data, files={"_": ("", b"")}, headers=headers)
    assert r.status_code in (200, 201), r.text
    return r.json()


def _my_id(client) -> int:
    return client.get("/api/authentication/me").json()["user_id"]


def _self_envelope(client, headers):
    groups = client.get("/api/stories", headers=headers).json()["story_groups"]
    self_group = next(g for g in groups if g["is_self"])
    return self_group["stories"][0]["key_envelope"]


def test_story_hybrid_self_envelope_survives(client):
    u = make_user(client)
    h = u["headers"]
    uid = _my_id(client)
    env = _hybrid_env(uid)
    _create_story(client, h, [env])

    got = _self_envelope(client, h)
    assert got.get("hybrid") is True
    assert got["kyber_ciphertext"] == env["kyber_ciphertext"]
    assert got["x25519_ephemeral_pub"] == env["x25519_ephemeral_pub"]
    assert got["ciphertext"] == env["ciphertext"]
    assert "ephemeral_pub" not in got


def test_story_classical_envelope_still_works(client):
    u = make_user(client)
    h = u["headers"]
    uid = _my_id(client)
    env = _classical_env(uid)
    _create_story(client, h, [env])

    got = _self_envelope(client, h)
    assert got["ephemeral_pub"] == env["ephemeral_pub"]
    assert got["ciphertext"] == env["ciphertext"]
    assert "kyber_ciphertext" not in got
    assert "hybrid" not in got


def test_story_delivered_to_contact_by_user_id(client):
    """Live keying-фикс: конверт для контакта хранится по РЕАЛЬНОМУ peer user_id,
    и контакт получает свой key_envelope через GET /api/stories. (Классика —
    проверяем keying, не PQ.) Раньше клиент keying'овал по contact_id (row id) →
    read-сторона `user_id == u.id` не матчила → контакт-доставка была сломана."""
    author = make_user(client)
    author_id = author["data"].get("user_id") or author["data"].get("id")
    viewer = make_user(client)
    viewer_id = viewer["data"].get("user_id") or viewer["data"].get("id")

    # viewer добавляет author в контакты (иначе не увидит его stories)
    v_h = login_user(client, viewer["username"], viewer["password"])
    r = client.post("/api/contacts", json={"user_id": author_id}, headers=v_h)
    if r.status_code not in (200, 201):
        import pytest
        pytest.skip(f"contact add unavailable: {r.status_code} {r.text}")

    # author создаёт story с конвертом, ключёванным по РЕАЛЬНОМУ user_id viewer'а
    a_h = login_user(client, author["username"], author["password"])
    env = {"user_id": viewer_id, "ephemeral_pub": secrets.token_hex(32), "ciphertext": secrets.token_hex(60)}
    _create_story(client, a_h, [env])

    # viewer видит story автора со своим key_envelope
    v_h = login_user(client, viewer["username"], viewer["password"])
    groups = client.get("/api/stories", headers=v_h).json()["story_groups"]
    author_group = next((g for g in groups if g["user_id"] == author_id and not g["is_self"]), None)
    assert author_group is not None, groups
    env_got = author_group["stories"][0]["key_envelope"]
    assert env_got["ephemeral_pub"] == env["ephemeral_pub"]
    assert env_got["ciphertext"] == env["ciphertext"]


def test_contacts_endpoint_carries_kyber_pub_sig(client):
    """/api/contacts отдаёт kyber_public_key + sig контакта — capability-канал stories."""
    # peer регистрируется первым и активен → публикует Kyber (K2)
    peer = make_user(client)
    peer_id = peer["data"].get("user_id") or peer["data"].get("id")
    pub, sig = secrets.token_hex(1184), secrets.token_hex(64)
    client.post("/api/keys/kyber", json={"kyber_public_key": pub, "kyber_public_key_sig": sig},
                headers=peer["headers"])

    # owner логинится последним (cookie → owner) и добавляет peer в контакты
    owner = make_user(client)
    o_h = login_user(client, owner["username"], owner["password"])
    r = client.post("/api/contacts", json={"user_id": peer_id}, headers=o_h)
    if r.status_code not in (200, 201):
        import pytest
        pytest.skip(f"contact add unavailable: {r.status_code} {r.text}")

    contacts = client.get("/api/contacts", headers=o_h).json()
    lst = contacts.get("contacts", contacts)
    row = next((c for c in lst if (c.get("user_id") == peer_id)), None)
    assert row is not None, lst
    assert row["kyber_public_key"] == pub
    assert row["kyber_public_key_sig"] == sig
