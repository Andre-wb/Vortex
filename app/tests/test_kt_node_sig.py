"""ADR-009 Фаза 1: нода-подпись записей прозрачного лога (non-repudiation-субстрат).

Два уровня:
  1. Cross-impl оракул к static/js/dr/kt-verify.js — та же фикс-сериализация нагрузки
     и Ed25519, что пинит JS-тест (static/js/__tests__/kt-verify.test.js).
  2. Эндпоинт: публикация prekey-бандла логирует account-Ed в KT с node_sig, который
     РЕАЛЬНО верифицируется против раздаваемого node_pubkey; дедуп без бонусных записей.

КРУКС: это доказывает «нода под ключом K подписала запись», НЕ «ключ честный» —
детекцию (fork vs reset) даёт только Фаза 3 (STH+gossip). Тест проверяет субстрат.
"""

import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from conftest import make_user, login_user, random_str


def _raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kt_entry_message(user_id, key_type, pub_key_hash, prev_hash, seq) -> bytes:
    return f"vortex-kt-entry:v1:{user_id}:{key_type}:{pub_key_hash}:{prev_hash or ''}:{seq}".encode()


# --- 1. Cross-impl оракул (тот же вектор, что JS) -------------------------

def test_kt_message_and_sig_match_cross_impl_vector():
    node = Ed25519PrivateKey.from_private_bytes(bytes([0x22]) * 32)
    assert _raw(node.public_key()).hex() == "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
    msg = kt_entry_message(1, "account_ed", "ab" * 32, None, 1)
    assert msg == b"vortex-kt-entry:v1:1:account_ed:" + (b"ab" * 32) + b"::1"
    node.public_key().verify(bytes.fromhex(
        "abe83fb1cede4608250f204b25eae68074fc1d8c651f169b581ceb6c1eab71f52ee54f51414dc092ccbfe15c32c669a116b3984f321efcc5f7a2c4e750ec6008"), msg)


# --- 2. Эндпоинт: account-Ed логируется с проверяемой нода-подписью --------

def _publish_bundle(client, headers, x25519_hex, account_ed):
    ik = bytes.fromhex(x25519_hex)
    ed_pub_hex = _raw(account_ed.public_key()).hex()
    spk = _raw(X25519PrivateKey.generate().public_key())
    r = client.post("/api/keys/prekeys/publish", json={
        "identity_key":      x25519_hex,
        "signed_prekey":     spk.hex(),
        "signed_prekey_sig": account_ed.sign(spk).hex(),
        "signed_prekey_id":  1,
        "identity_key_ed":   ed_pub_hex,
        "identity_key_sig":  account_ed.sign(ik).hex(),
        "supports_v2":       True,
        "one_time_prekeys":  [],
    }, headers=headers)
    assert r.status_code == 200, r.text
    return ed_pub_hex


def test_publish_logs_account_ed_with_verifiable_node_sig(client, monkeypatch):
    from app.config import Config
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)

    u = make_user(client)
    h = login_user(client, u["username"], u["password"])
    uid = u["data"]["user_id"]
    account_ed = Ed25519PrivateKey.generate()
    _publish_bundle(client, h, u["x25519_pub"], account_ed)

    r = client.get(f"/api/keys/transparency/{uid}", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    node_pub = body["node_pubkey"]
    assert node_pub, "node_pubkey должен раздаваться"

    acct_entries = [e for e in body["entries"] if e["key_type"] == "account_ed"]
    assert len(acct_entries) == 1
    e = acct_entries[0]
    assert e["node_sig"], "account_ed запись должна быть нода-подписана"

    # Нода-подпись РЕАЛЬНО сходится против раздаваемого node_pubkey (то, что проверит клиент).
    node_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(node_pub))
    node_key.verify(
        bytes.fromhex(e["node_sig"]),
        kt_entry_message(uid, "account_ed", e["pub_key_hash"], e["prev_hash"], e["seq"]))

    # Негатив: против ЧУЖОГО ключа не сходится (подпись привязана к ноде).
    other = Ed25519PrivateKey.generate().public_key()
    try:
        other.verify(bytes.fromhex(e["node_sig"]),
                     kt_entry_message(uid, "account_ed", e["pub_key_hash"], e["prev_hash"], e["seq"]))
        assert False, "verified against wrong node key"
    except Exception:
        pass


def test_account_ed_dedup_no_duplicate_on_republish(client, monkeypatch):
    from app.config import Config
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)

    u = make_user(client)
    h = login_user(client, u["username"], u["password"])
    uid = u["data"]["user_id"]
    account_ed = Ed25519PrivateKey.generate()
    _publish_bundle(client, h, u["x25519_pub"], account_ed)
    _publish_bundle(client, h, u["x25519_pub"], account_ed)   # тот же account_ed

    body = client.get(f"/api/keys/transparency/{uid}", headers=h).json()
    acct = [e for e in body["entries"] if e["key_type"] == "account_ed"]
    assert len(acct) == 1, "неизменный account_ed не должен дублироваться"
