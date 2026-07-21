"""Серверный конец пары к key-login фиксу: /api/authentication/login-key ПРИНИМАЕТ
корректный HKDF-proof (тот, что теперь считает клиентский auth.js:_computeKeyLoginProof).

Раньше клиент слал HMAC(СЫРОЙ X25519 DH), а сервер ждёт
HMAC(derive_x25519_session_key(...)=HKDF(salt=sorted)) → 401, фича тихо мертва.
Ни один тест не пинил УСПЕШНЫЙ proof — эта петля закрывается здесь (сервер-конец)
+ key-login-proof-cross-impl.test.js (клиент-конец, тот же вектор транзитивно).
"""

import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from starlette.testclient import TestClient

from conftest import random_str, random_digits, _phone_prefix
from app.security.crypto import derive_x25519_session_key
from app.main import app

_PW = "Str0ng_abcd!@"


def _raw_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_login_key_valid_hkdf_proof_accepted():
    with TestClient(app, raise_server_exceptions=False) as tc:
        client_priv = X25519PrivateKey.generate()
        client_priv_b = client_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        client_pub = _raw_pub(client_priv).hex()

        # Регистрируем юзера с ИМЕННО этим x25519 pub (challenge к нему привяжется).
        tag = random_str(8)
        username = f"kl_{tag}"
        phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
        r = tc.post("/api/authentication/register", json={
            "username": username, "password": _PW, "display_name": f"KL {tag}",
            "phone": phone, "avatar_emoji": "\U0001f511", "x25519_public_key": client_pub,
        })
        assert r.status_code in (200, 201), r.text

        csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        ch = tc.get("/api/authentication/challenge", params={"identifier": username}).json()
        assert "challenge_id" in ch and "server_pubkey" in ch, ch

        # Клиентский proof: derive(client_priv, server_pub) симметричен серверному
        # derive(server_priv, client_pub) — тот же HKDF(salt=sorted) shared.
        server_pub = bytes.fromhex(ch["server_pubkey"])
        shared = derive_x25519_session_key(client_priv_b, server_pub)
        if isinstance(shared, list):
            shared = bytes(shared)
        proof = hmac.new(shared, bytes.fromhex(ch["challenge"]), hashlib.sha256).hexdigest()

        r = tc.post("/api/authentication/login-key", json={
            "challenge_id": ch["challenge_id"], "pubkey": client_pub, "proof": proof,
        }, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text   # сервер ПРИНЯЛ корректный HKDF-proof

        # Негатив: HMAC над СЫРЫМ DH (старый клиентский баг) — сервер ОТВЕРГ бы.
        raw_shared = client_priv.exchange(X25519PublicKey.from_public_bytes(server_pub))
        raw_proof = hmac.new(raw_shared, bytes.fromhex(ch["challenge"]), hashlib.sha256).hexdigest()
        assert raw_proof != proof   # старый диалект не сошёлся бы (доказывает, что фикс нужен)
