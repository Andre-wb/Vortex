"""ADR-008 G1: GET /api/rooms/{id}/member-keys — единая точка сверки ключей участников.

Load-bearing: отданная цепочка ДОЛЖНА реально верифицироваться клиентом —
edVerify(identity_key_ed, x25519, identity_key_sig) и edVerify(ed, kyber, kyber_sig)
проходят, т.е. account Ed транзитивно покрывает X25519+Kyber. Плюс membership-гейт.
"""

import secrets

from conftest import login_user, make_user, random_str
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _publish_identity_chain(client, headers, x25519_hex, account_ed):
    """Публикует prekey-бандл (identity_key=x25519, подписан account_ed) + kyber-подпись."""
    ik_bytes = bytes.fromhex(x25519_hex)
    ed_pub_hex = _raw(account_ed.public_key()).hex()
    spk = X25519PrivateKey.generate()
    spk_pub = _raw(spk.public_key())

    r = client.post(
        "/api/keys/prekeys/publish",
        json={
            "identity_key": x25519_hex,
            "signed_prekey": spk_pub.hex(),
            "signed_prekey_sig": account_ed.sign(spk_pub).hex(),
            "signed_prekey_id": 1,
            "identity_key_ed": ed_pub_hex,
            "identity_key_sig": account_ed.sign(ik_bytes).hex(),  # account Ed подписал X25519
            "supports_v2": True,
            "one_time_prekeys": [],
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text

    kyber_pub = secrets.token_bytes(1184)  # синтетический ML-KEM pub
    r = client.post(
        "/api/keys/kyber",
        json={
            "kyber_public_key": kyber_pub.hex(),
            "kyber_public_key_sig": account_ed.sign(kyber_pub).hex(),
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return ed_pub_hex, kyber_pub.hex()


def _create_room(client, headers):
    r = client.post(
        "/api/rooms",
        json={
            "name": f"g1_{random_str()}",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        },
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text
    body = r.json()
    return body.get("id") or body.get("room", {}).get("id")


def test_member_keys_chain_verifies(client, monkeypatch):
    from app.config import Config

    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)

    member = make_user(client)
    h = login_user(client, member["username"], member["password"])
    x25519_hex = member["x25519_pub"]
    account_ed = Ed25519PrivateKey.generate()
    ed_pub_hex, _kyber_hex = _publish_identity_chain(client, h, x25519_hex, account_ed)

    room_id = _create_room(client, h)
    r = client.get(f"/api/rooms/{room_id}/member-keys", headers=h)
    assert r.status_code == 200, r.text
    entry = next(m for m in r.json()["members"] if m["user_id"] == member["data"]["user_id"])

    # Корень: account Ed отдан.
    assert entry["identity_key_ed"] == ed_pub_hex
    # X25519-обёрточный = account identity_key (тот, что подписывает identity_key_sig).
    assert entry["x25519_public_key"] == x25519_hex
    ed = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed_pub_hex))
    # Цепочка РЕАЛЬНО сходится (то, что проверит клиент в G2):
    ed.verify(bytes.fromhex(entry["identity_key_sig"]), bytes.fromhex(entry["x25519_public_key"]))
    ed.verify(bytes.fromhex(entry["kyber_public_key_sig"]), bytes.fromhex(entry["kyber_public_key"]))

    # Негатив: подпись НЕ проходит против ЧУЖОГО Ed (доказывает, что sig привязан к корню).
    other = Ed25519PrivateKey.generate().public_key()
    try:
        other.verify(bytes.fromhex(entry["identity_key_sig"]), bytes.fromhex(entry["x25519_public_key"]))
        raise AssertionError("sig verified against wrong Ed — binding broken")
    except InvalidSignature:
        pass


def test_member_keys_includes_self(client):
    """Ответ ОБЯЗАН содержать запись самого вызывающего.

    Load-bearing для room safety number: код считается по account-Ed ВСЕХ
    участников из этого ответа. Совпадёт у всех только если каждый видит одно и то
    же множество — а значит и себя. Исключи self — у каждого своё множество, коды
    разойдутся у всех, а фича молча сломается (крит. приёмки #5).
    """
    member = make_user(client)
    h = login_user(client, member["username"], member["password"])
    room_id = _create_room(client, h)

    r = client.get(f"/api/rooms/{room_id}/member-keys", headers=h)
    assert r.status_code == 200, r.text
    ids = {m["user_id"] for m in r.json()["members"]}
    assert member["data"]["user_id"] in ids, "member-keys не содержит self → room_sn разойдётся"


def test_member_keys_requires_membership(client):
    owner = make_user(client)
    login_user(client, owner["username"], owner["password"])
    room_id = _create_room(client, owner["headers"])

    outsider = make_user(client)
    ho = login_user(client, outsider["username"], outsider["password"])
    r = client.get(f"/api/rooms/{room_id}/member-keys", headers=ho)
    assert r.status_code == 403, r.text
