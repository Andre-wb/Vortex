"""P2-тесты: публикация per-device Kyber pre-key (PQXDH) в prekey-бандле.

Устройство публикует ML-KEM-768 Kyber pre-key public + подпись device signing-
ключом (та же цепочка, что SPK). Сервер длину проверяет и (при наличии
device_sign_pub) верифицирует подпись против него — НЕ против identity_key_ed.
Ключевая проверка плумбинга: по ответу /devices можно верифицировать
device_kyber_sig над СЫРЫМИ байтами kyber pub — то, что сделает отправитель (P5).

Kyber pub здесь синтетический (1184 случайных байта): сервер его не декапсулирует,
только длину и Ed25519-подпись над ним — реальный ML-KEM не нужен.
"""

import secrets

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from starlette.testclient import TestClient

from conftest import random_str, random_digits, _phone_prefix
from app.config import Config
from app.main import app

_PW = "Str0ng_abcd!@"
_KYBER_PUB_LEN = 1184


def _x25519_pub_hex() -> str:
    return X25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _build_bundle_with_kyber(account_ed: Ed25519PrivateKey, cid_hex: str, *,
                             with_device=True, tamper_kyber_sig=False,
                             bad_kyber_len=False, n_opk=2):
    """publish-тело с per-device Kyber pre-key. Kyber pub подписан device signing-
    ключом (когда with_device); при with_device=False device_sign_pub опущен."""
    ik_hex = _x25519_pub_hex()
    ik_bytes = bytes.fromhex(ik_hex)
    spk = X25519PrivateKey.generate()
    spk_pub = spk.public_key().public_bytes_raw()

    device_sign = Ed25519PrivateKey.generate()
    dev_sign_hex = device_sign.public_key().public_bytes_raw().hex()

    kyber_pub = secrets.token_bytes(31 if bad_kyber_len else _KYBER_PUB_LEN)
    # Kyber pub подписывает device signing-ключ (как SPK); при no-device — тоже
    # им, но device_sign_pub не публикуем → сервер подпись не проверяет.
    kyber_sig = device_sign.sign(kyber_pub)
    if tamper_kyber_sig:
        kyber_sig = bytes([kyber_sig[0] ^ 0xFF]) + kyber_sig[1:]

    body = {
        "identity_key":      ik_hex,
        "signed_prekey":     spk_pub.hex(),
        "signed_prekey_sig": account_ed.sign(spk_pub).hex(),
        "signed_prekey_id":  1,
        "identity_key_ed":   account_ed.public_key().public_bytes_raw().hex(),
        "identity_key_sig":  account_ed.sign(ik_bytes).hex(),
        "supports_v2":       True,
        "device_x3dh_pub":   _x25519_pub_hex(),
        "device_kyber_pub":  kyber_pub.hex(),
        "device_kyber_sig":  kyber_sig.hex(),
        "device_kyber_id":   1,
        "one_time_prekeys":  [{"key_id": i, "public_key": _x25519_pub_hex()} for i in range(n_opk)],
    }
    if with_device:
        body["device_sign_pub"] = dev_sign_hex
    return body, device_sign


@pytest.fixture
def warn_only(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)


def _register(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    tc.post("/api/authentication/register", json={
        "username": f"pq_{tag}", "password": _PW, "display_name": f"PQ {tag}",
        "phone": phone, "avatar_emoji": "\U0001f511", "x25519_public_key": _x25519_pub_hex(),
    })
    return f"pq_{tag}"


def _login(tc, username, cid):
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post("/api/authentication/login",
            json={"phone_or_username": username, "password": _PW},
            headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
    return csrf


class TestKyberPrekeyPublish:

    def test_kyber_prekey_verifiable_from_fetch(self, warn_only):
        """Плумбинг: по ответу /devices device_kyber_sig верифицируется над сырыми
        байтами kyber pub против device_sign_pub — как сделает отправитель (P5)."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            csrf = _login(tc, username, cid)
            body, _ = _build_bundle_with_kyber(Ed25519PrivateKey.generate(), cid)
            r = tc.post("/api/keys/prekeys/publish", json=body,
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text

            me = tc.get("/api/authentication/me").json()
            b = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"][0]
            assert b["device_kyber_pub"] and b["device_kyber_sig"]
            assert b["device_kyber_id"] == 1
            assert len(bytes.fromhex(b["device_kyber_pub"])) == _KYBER_PUB_LEN
            # Подпись над СЫРЫМИ байтами kyber pub против device_sign_pub — не бросает.
            dev_sign = Ed25519PublicKey.from_public_bytes(bytes.fromhex(b["device_sign_pub"]))
            dev_sign.verify(bytes.fromhex(b["device_kyber_sig"]), bytes.fromhex(b["device_kyber_pub"]))

    def test_single_fetch_exposes_kyber(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            csrf = _login(tc, username, cid)
            body, _ = _build_bundle_with_kyber(Ed25519PrivateKey.generate(), cid)
            tc.post("/api/keys/prekeys/publish", json=body,
                    headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            me = tc.get("/api/authentication/me").json()
            single = tc.get(f"/api/keys/prekeys/{me['user_id']}").json()
            assert single["device_kyber_pub"] and single["device_kyber_sig"]
            assert single["device_kyber_id"] == 1

    def test_backward_compat_no_kyber(self, warn_only):
        """Бандл без Kyber-полей публикуется; kyber-поля в ответе null (классика)."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            csrf = _login(tc, username, cid)
            body, _ = _build_bundle_with_kyber(Ed25519PrivateKey.generate(), cid)
            for k in ("device_kyber_pub", "device_kyber_sig", "device_kyber_id"):
                body.pop(k)
            r = tc.post("/api/keys/prekeys/publish", json=body,
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text
            me = tc.get("/api/authentication/me").json()
            b = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"][0]
            assert b["device_kyber_pub"] is None
            assert b["device_kyber_sig"] is None
            assert b["device_kyber_id"] is None

    def test_no_device_path_kyber_stored_unverified(self, warn_only):
        """Kyber-поля без device_sign_pub — публикуются, сервер подпись не проверяет
        (как device_cert_sig). no-device путь — не таргет P5."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            csrf = _login(tc, username, cid)
            body, _ = _build_bundle_with_kyber(Ed25519PrivateKey.generate(), cid, with_device=False)
            assert "device_sign_pub" not in body
            r = tc.post("/api/keys/prekeys/publish", json=body,
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text
            me = tc.get("/api/authentication/me").json()
            b = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"][0]
            assert b["device_kyber_pub"] and b["device_sign_pub"] is None

    def test_bad_kyber_length_rejected(self, warn_only):
        """Kyber pub не 1184 байта → отвергается (pydantic min_length 2368 hex)."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            csrf = _login(tc, username, cid)
            body, _ = _build_bundle_with_kyber(Ed25519PrivateKey.generate(), cid, bad_kyber_len=True)
            r = tc.post("/api/keys/prekeys/publish", json=body,
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code in (400, 422)

    def test_tampered_kyber_sig_warn_only_accepts(self, warn_only):
        """Битая Kyber-подпись под warn-only принимается (как SPK), но НЕ верифицируется."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            csrf = _login(tc, username, cid)
            body, _ = _build_bundle_with_kyber(Ed25519PrivateKey.generate(), cid, tamper_kyber_sig=True)
            r = tc.post("/api/keys/prekeys/publish", json=body,
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text  # warn-only принял
            me = tc.get("/api/authentication/me").json()
            b = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"][0]
            dev_sign = Ed25519PublicKey.from_public_bytes(bytes.fromhex(b["device_sign_pub"]))
            with pytest.raises(InvalidSignature):
                dev_sign.verify(bytes.fromhex(b["device_kyber_sig"]), bytes.fromhex(b["device_kyber_pub"]))
