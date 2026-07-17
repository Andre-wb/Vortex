"""Тесты P1-реализации: публикация device-identity тройки и cert'а.

Устройство публикует публичные части тройки (device X3DH pub, device signing
pub, authorization-cert аккаунта над ними) вместе с prekey-бандлом. Cert подписан
аккаунтным Ed25519 над (client_device_id ‖ device_x3dh_pub ‖ device_sign_pub).
Ключевая проверка: по ответу fetch можно восстановить cert-сообщение и
верифицировать подпись против аккаунтного identity_key_ed — то, что понадобится
отправителю на fan-out (M3). Сам сервер cert НЕ проверяет.
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


def _x25519_pub_hex() -> str:
    return X25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _cert_message(cid_hex: str, x3dh_hex: str, sign_hex: str) -> bytes:
    """client_device_id(16) ‖ device_x3dh_pub(32) ‖ device_sign_pub(32) = 80 байт.
    Зеркалит certMessage() из static/js/dr/device-identity.js."""
    return bytes.fromhex(cid_hex) + bytes.fromhex(x3dh_hex) + bytes.fromhex(sign_hex)


def _build_bundle_with_device(account_ed: Ed25519PrivateKey, cid_hex: str, *,
                              omit_cert=False, tamper_cert=False, n_opk=2):
    """Собирает publish-тело с device-identity тройкой; cert подписан account_ed."""
    ik_hex = _x25519_pub_hex()
    ik_bytes = bytes.fromhex(ik_hex)
    spk = X25519PrivateKey.generate()
    spk_pub = spk.public_key().public_bytes_raw()

    dev_x3dh_hex = _x25519_pub_hex()
    dev_sign_hex = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    cert = account_ed.sign(_cert_message(cid_hex, dev_x3dh_hex, dev_sign_hex))
    if tamper_cert:
        cert = bytes([cert[0] ^ 0xFF]) + cert[1:]

    body = {
        "identity_key":      ik_hex,
        "signed_prekey":     spk_pub.hex(),
        "signed_prekey_sig": account_ed.sign(spk_pub).hex(),
        "signed_prekey_id":  1,
        "identity_key_ed":   account_ed.public_key().public_bytes_raw().hex(),
        "identity_key_sig":  account_ed.sign(ik_bytes).hex(),
        "supports_v2":       True,
        "device_x3dh_pub":   dev_x3dh_hex,
        "device_sign_pub":   dev_sign_hex,
        "one_time_prekeys":  [{"key_id": i, "public_key": _x25519_pub_hex()} for i in range(n_opk)],
    }
    if not omit_cert:
        body["device_cert_sig"] = cert.hex()
    return body


@pytest.fixture
def warn_only(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)


def _register(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    tc.post("/api/authentication/register", json={
        "username": f"di_{tag}", "password": _PW, "display_name": f"DI {tag}",
        "phone": phone, "avatar_emoji": "\U0001f511", "x25519_public_key": _x25519_pub_hex(),
    })
    return f"di_{tag}"


def _login(tc, username, cid):
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post("/api/authentication/login",
            json={"phone_or_username": username, "password": _PW},
            headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
    return csrf


class TestDeviceIdentityPublish:

    def test_cert_is_verifiable_from_fetch_response(self, warn_only):
        """Главный тест плумбинга: по ответу /devices восстанавливаем cert-сообщение
        и верифицируем подпись против identity_key_ed — как сделает отправитель."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            account_ed = Ed25519PrivateKey.generate()
            csrf = _login(tc, username, cid)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle_with_device(account_ed, cid),
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text

            me = tc.get("/api/authentication/me").json()
            bundles = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"]
            assert len(bundles) == 1
            b = bundles[0]
            # Все поля тройки + cert присутствуют
            assert b["device_x3dh_pub"] and b["device_sign_pub"] and b["device_cert_sig"]
            assert b["client_device_id"] == cid
            # Восстанавливаем cert-сообщение из ответа и проверяем подпись
            msg = _cert_message(b["client_device_id"], b["device_x3dh_pub"], b["device_sign_pub"])
            ed_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(b["identity_key_ed"]))
            ed_pub.verify(bytes.fromhex(b["device_cert_sig"]), msg)  # не бросает → cert валиден

    def test_single_fetch_exposes_device_identity(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            account_ed = Ed25519PrivateKey.generate()
            csrf = _login(tc, username, cid)
            tc.post("/api/keys/prekeys/publish",
                    json=_build_bundle_with_device(account_ed, cid),
                    headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            me = tc.get("/api/authentication/me").json()
            single = tc.get(f"/api/keys/prekeys/{me['user_id']}").json()
            assert single["device_x3dh_pub"] and single["device_sign_pub"]
            assert single["device_cert_sig"] and single["client_device_id"] == cid

    def test_tampered_cert_fails_verification(self, warn_only):
        """Битый cert публикуется (сервер не проверяет), но НЕ верифицируется."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            account_ed = Ed25519PrivateKey.generate()
            csrf = _login(tc, username, cid)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle_with_device(account_ed, cid, tamper_cert=True),
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text  # сервер cert не валидирует

            me = tc.get("/api/authentication/me").json()
            b = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"][0]
            msg = _cert_message(b["client_device_id"], b["device_x3dh_pub"], b["device_sign_pub"])
            ed_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(b["identity_key_ed"]))
            with pytest.raises(InvalidSignature):
                ed_pub.verify(bytes.fromhex(b["device_cert_sig"]), msg)

    def test_deferred_cert_null_when_omitted(self, warn_only):
        """Свежелинкованное устройство без аккаунтного Ed25519 шлёт cert=null —
        тройка публикуется, cert откладывается."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            account_ed = Ed25519PrivateKey.generate()
            csrf = _login(tc, username, cid)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle_with_device(account_ed, cid, omit_cert=True),
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code == 200, r.text
            me = tc.get("/api/authentication/me").json()
            b = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"][0]
            assert b["device_x3dh_pub"] and b["device_sign_pub"]
            assert b["device_cert_sig"] is None

    def test_bad_device_field_length_rejected(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            username = _register(tc)
            cid = secrets.token_hex(16)
            account_ed = Ed25519PrivateKey.generate()
            csrf = _login(tc, username, cid)
            body = _build_bundle_with_device(account_ed, cid)
            body["device_x3dh_pub"] = "aa" * 31  # 31 байт вместо 32 → pydantic min_length
            r = tc.post("/api/keys/prekeys/publish", json=body,
                        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})
            assert r.status_code in (400, 422)
