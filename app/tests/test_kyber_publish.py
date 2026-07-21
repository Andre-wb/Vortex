"""K2: публикация аккаунтного Kyber-pub (ML-KEM-768) клиентом.

POST /api/keys/kyber хранит pub + Ed25519-подпись; профиль их отдаёт (отправитель
проверит подпись). Серверная keygen убрана (E2E — приватный только у клиента).
"""

import secrets

from starlette.testclient import TestClient

from conftest import random_str, random_digits, _phone_prefix
from app.main import app

_PW = "Str0ng_abcd!@"


def _register_login(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    tc.post("/api/authentication/register", json={
        "username": f"kb_{tag}", "password": _PW, "display_name": f"KB {tag}",
        "phone": phone, "avatar_emoji": "\U0001f511", "x25519_public_key": secrets.token_hex(32),
    })
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post("/api/authentication/login",
            json={"phone_or_username": f"kb_{tag}", "password": _PW},
            headers={"X-CSRF-Token": csrf})
    return csrf


def test_publish_kyber_stored_and_returned():
    with TestClient(app, raise_server_exceptions=False) as tc:
        csrf = _register_login(tc)
        h = {"X-CSRF-Token": csrf}

        # Свежая регистрация: серверная keygen убрана → kyber ещё нет
        me = tc.get("/api/authentication/me").json()
        assert me.get("kyber_public_key") in (None, "")

        pub = secrets.token_hex(1184)   # ML-KEM-768 pub = 1184 байта
        sig = secrets.token_hex(64)     # Ed25519 подпись = 64 байта
        r = tc.post("/api/keys/kyber", json={"kyber_public_key": pub, "kyber_public_key_sig": sig}, headers=h)
        assert r.status_code == 200, r.text

        me2 = tc.get("/api/authentication/me").json()
        assert me2["kyber_public_key"] == pub
        assert me2["kyber_public_key_sig"] == sig


def test_publish_kyber_rejects_bad_length():
    with TestClient(app, raise_server_exceptions=False) as tc:
        csrf = _register_login(tc)
        h = {"X-CSRF-Token": csrf}
        # pub не 1184 байта → 400/422
        r = tc.post("/api/keys/kyber",
                    json={"kyber_public_key": secrets.token_hex(100), "kyber_public_key_sig": secrets.token_hex(64)},
                    headers=h)
        assert r.status_code in (400, 422)
