"""P6-тесты: one-time Kyber pre-keys (PQOPK) — публикация и claim.

PQOPK расходуется ТОЛЬКО при want_kyber=true (сессия реально идёт в PQ) — иначе
не-PQ трафик (флаг-off отправители = дефолт) выжигал бы пул. Исчерпание → null
(X3DH-PQ идёт на last-resort PQSPK). Kyber pub синтетический (сервер только
длину проверяет и хранит).
"""

import secrets

import pytest
from conftest import _phone_prefix, random_digits, random_str
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from starlette.testclient import TestClient

from app.config import Config
from app.main import app

_PW = "Str0ng_abcd!@"


def _x25519_pub_hex() -> str:
    return X25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _bundle_with_pqopks(account_ed, n_pqopk=2, base_id=1000):
    ik_hex = _x25519_pub_hex()
    spk = X25519PrivateKey.generate()
    spk_pub = spk.public_key().public_bytes_raw()
    return {
        "identity_key": ik_hex,
        "signed_prekey": spk_pub.hex(),
        "signed_prekey_sig": account_ed.sign(spk_pub).hex(),
        "signed_prekey_id": 1,
        "identity_key_ed": account_ed.public_key().public_bytes_raw().hex(),
        "identity_key_sig": account_ed.sign(bytes.fromhex(ik_hex)).hex(),
        "supports_v2": True,
        "one_time_kyber_prekeys": [
            {"key_id": base_id + i, "public_key": secrets.token_bytes(1184).hex()} for i in range(n_pqopk)
        ],
    }


@pytest.fixture
def warn_only(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)


def _register(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    tc.post(
        "/api/authentication/register",
        json={
            "username": f"po_{tag}",
            "password": _PW,
            "display_name": f"PO {tag}",
            "phone": phone,
            "avatar_emoji": "\U0001f511",
            "x25519_public_key": _x25519_pub_hex(),
        },
    )
    return f"po_{tag}"


def _login(tc, username):
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post(
        "/api/authentication/login",
        json={"phone_or_username": username, "password": _PW},
        headers={"X-CSRF-Token": csrf},
    )
    return csrf


def _publish_and_uid(tc, csrf, body):
    r = tc.post("/api/keys/prekeys/publish", json=body, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    return tc.get("/api/authentication/me").json()["user_id"]


def _claim(tc, csrf, uid, want_kyber):
    return tc.post(
        f"/api/keys/prekeys/{uid}/claim-opk", json={"want_kyber": want_kyber}, headers={"X-CSRF-Token": csrf}
    ).json()


class TestKyberOneTimePrekey:
    def test_claim_want_kyber_returns_and_consumes(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            u = _register(tc)
            csrf = _login(tc, u)
            uid = _publish_and_uid(tc, csrf, _bundle_with_pqopks(Ed25519PrivateKey.generate(), 2))
            first = _claim(tc, csrf, uid, True)
            assert first["one_time_kyber_prekey"] is not None
            assert first["one_time_kyber_prekey_id"] in (1000, 1001)
            second = _claim(tc, csrf, uid, True)
            assert second["one_time_kyber_prekey_id"] != first["one_time_kyber_prekey_id"]  # другой
            third = _claim(tc, csrf, uid, True)
            assert third["one_time_kyber_prekey"] is None  # исчерпан

    def test_want_kyber_false_does_not_consume(self, warn_only):
        """fork-a: не-PQ claim (want_kyber=false) НЕ трогает пул PQOPK."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            u = _register(tc)
            csrf = _login(tc, u)
            uid = _publish_and_uid(tc, csrf, _bundle_with_pqopks(Ed25519PrivateKey.generate(), 2))
            no_pq = _claim(tc, csrf, uid, False)
            assert no_pq["one_time_kyber_prekey"] is None  # не отдан
            # пул НЕ израсходован — оба PQOPK ещё доступны
            assert _claim(tc, csrf, uid, True)["one_time_kyber_prekey"] is not None
            assert _claim(tc, csrf, uid, True)["one_time_kyber_prekey"] is not None
            assert _claim(tc, csrf, uid, True)["one_time_kyber_prekey"] is None

    def test_bad_pqopk_length_rejected(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            u = _register(tc)
            csrf = _login(tc, u)
            body = _bundle_with_pqopks(Ed25519PrivateKey.generate(), 1)
            body["one_time_kyber_prekeys"][0]["public_key"] = "aa" * 100  # не 1184 → pydantic min_length
            r = tc.post("/api/keys/prekeys/publish", json=body, headers={"X-CSRF-Token": csrf})
            assert r.status_code in (400, 422)

    def test_no_pqopks_published_claim_returns_null(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            u = _register(tc)
            csrf = _login(tc, u)
            uid = _publish_and_uid(tc, csrf, _bundle_with_pqopks(Ed25519PrivateKey.generate(), 0))
            assert _claim(tc, csrf, uid, True)["one_time_kyber_prekey"] is None
