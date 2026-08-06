"""ADR-008 §4.2: кросс-девайсный мирор OOB-верификаций.

Два уровня:
  1. Cross-impl оракул к static/js/dr/verify-mirror.js — та же сериализация payload
     и та же цепочка подписей (device-key подписал payload, account-Ed подписал
     device-cert), что пинит JS-тест (static/js/__tests__/verify-mirror.test.js).
  2. Эндпоинт: сервер — НЕподделываемое хранилище, owner-scoped (чужие записи
     недоступны), rollback-guard по signed_at.
"""

from conftest import login_user, make_user
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def attest_payload(owner, peer, ed, state, ts) -> bytes:
    return f"vortex-verify-attest:v1:{owner}:{peer}:{ed.lower()}:{state}:{ts}".encode()


# --- 1. Cross-impl оракул (пинит тот же вектор, что JS) --------------------

_ACCT = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_DEV = Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32)
_ACCT_PUB = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
_DEV_PUB = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
_DEVICE_ID = "00112233445566778899aabbccddeeff"
_X3DH = "a1" * 32
_ED = "cd" * 32


def test_payload_and_signatures_match_cross_impl_vector():
    assert _raw(_ACCT.public_key()).hex() == _ACCT_PUB
    assert _raw(_DEV.public_key()).hex() == _DEV_PUB

    payload = attest_payload(1, 2, _ED, "verified", 1700000000)
    assert payload == b"vortex-verify-attest:v1:1:2:" + _ED.encode() + b":verified:1700000000"

    # certMessage = device_id(16) ‖ x3dh(32) ‖ sign_pub(32)
    cert_msg = bytes.fromhex(_DEVICE_ID) + bytes.fromhex(_X3DH) + bytes.fromhex(_DEV_PUB)
    # Обе подписи РЕАЛЬНО сходятся (то, что проверит JS-устройство-потребитель).
    _ACCT.public_key().verify(bytes.fromhex(
        "811510219d61f6af65bb3714e30a4f75a6605ce093a9b5f63a1ddad663effb164ca74fff1145fdf82de61078251ddcb85f693de76faa8ae09ff1e80dc6697205"), cert_msg)
    _DEV.public_key().verify(bytes.fromhex(
        "1e655a9648896fef959224953ce66de958c6bc62416b089ad78607046d64945b399b04c1195b229f7a12a19d18d0e397532ed80332859610759851c7a7b1d80c"), payload)


# --- 2. Эндпоинт: хранилище, owner-scope, rollback-guard ------------------

def _attestation(peer_id, ed=_ED, state="verified", signed_at=1700000000):
    return {
        "peer_user_id": peer_id,
        "verified_ed": ed,
        "state": state,
        "signed_at": signed_at,
        "client_device_id": _DEVICE_ID,
        "device_x3dh_pub": _X3DH,
        "device_sign_pub": _DEV_PUB,
        "device_cert_sig": "ab" * 64,
        "attest_sig": "cd" * 64,
    }


def test_store_and_fetch_own_attestation(client):
    owner = make_user(client)
    h = login_user(client, owner["username"], owner["password"])
    peer = make_user(client)
    peer_id = peer["data"]["user_id"]

    r = client.post("/api/verify/attestations", json=_attestation(peer_id), headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is True

    r = client.get("/api/verify/attestations", headers=h)
    assert r.status_code == 200, r.text
    rows = r.json()["attestations"]
    assert any(a["peer_user_id"] == peer_id and a["state"] == "verified" for a in rows)


def test_attestations_are_owner_scoped(client):
    a = make_user(client)
    ha = login_user(client, a["username"], a["password"])
    peer = make_user(client)
    client.post("/api/verify/attestations", json=_attestation(peer["data"]["user_id"]), headers=ha)

    b = make_user(client)
    hb = login_user(client, b["username"], b["password"])
    r = client.get("/api/verify/attestations", headers=hb)
    assert r.status_code == 200, r.text
    # B не видит атестаций A.
    assert r.json()["attestations"] == []


def test_rollback_guard_older_signed_at_ignored(client):
    owner = make_user(client)
    h = login_user(client, owner["username"], owner["password"])
    peer_id = make_user(client)["data"]["user_id"]

    # Свежая запись.
    client.post("/api/verify/attestations", json=_attestation(peer_id, state="revoked", signed_at=2000), headers=h)
    # Реплей старой verified не должен откатить revoked.
    r = client.post("/api/verify/attestations", json=_attestation(peer_id, state="verified", signed_at=1000), headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is False

    rows = client.get("/api/verify/attestations", headers=h).json()["attestations"]
    row = next(a for a in rows if a["peer_user_id"] == peer_id)
    assert row["state"] == "revoked" and row["signed_at"] == 2000


def test_bad_hex_rejected(client):
    owner = make_user(client)
    h = login_user(client, owner["username"], owner["password"])
    peer_id = make_user(client)["data"]["user_id"]
    bad = _attestation(peer_id)
    bad["verified_ed"] = "xyz"
    r = client.post("/api/verify/attestations", json=bad, headers=h)
    assert r.status_code == 400, r.text
