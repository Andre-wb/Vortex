"""M4b: linking несёт тройку нового устройства и аккаунт-материал (cert +
account_ed_pub + identity_key_sig) от одобряющего к новому устройству.

Проверяется серверный плумбинг: /link/request принимает тройку, /link/{code}
её отдаёт, /approve принимает аккаунт-материал, /poll отдаёт его. Сервер только
ретранслирует (A1), подписи не проверяет.
"""

import secrets

from starlette.testclient import TestClient

from conftest import random_str, random_digits, _phone_prefix
from app.main import app

_PW = "Str0ng_abcd!@"


def _register_login(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    ik = secrets.token_hex(32)
    tc.post("/api/authentication/register", json={
        "username": f"lk_{tag}", "password": _PW, "display_name": f"LK {tag}",
        "phone": phone, "avatar_emoji": "\U0001f511", "x25519_public_key": ik,
    })
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post("/api/authentication/login",
            json={"phone_or_username": f"lk_{tag}", "password": _PW},
            headers={"X-CSRF-Token": csrf})
    return csrf


def test_link_flow_carries_triple_and_cert_material():
    with TestClient(app, raise_server_exceptions=False) as tc:
        csrf = _register_login(tc)
        h = {"X-CSRF-Token": csrf}

        # Новое устройство: запрос линковки со своей тройкой
        triple = {
            "new_device_pub": secrets.token_hex(32),
            "new_device_x3dh_pub": secrets.token_hex(32),
            "new_device_sign_pub": secrets.token_hex(32),
            "new_device_client_id": secrets.token_hex(16),
        }
        r = tc.post("/api/keys/link/request", json=triple, headers=h)
        assert r.status_code == 200, r.text
        code = r.json()["link_code"]
        req_id = r.json()["request_id"]

        # Одобряющий: GET по коду возвращает тройку нового устройства
        g = tc.get(f"/api/keys/link/{code}", headers=h).json()
        assert g["new_device_x3dh_pub"] == triple["new_device_x3dh_pub"]
        assert g["new_device_sign_pub"] == triple["new_device_sign_pub"]
        assert g["new_device_client_id"] == triple["new_device_client_id"]

        # Одобряющий: approve с аккаунт-материалом (cert + account_ed_pub + idSig)
        material = {
            "encrypted_keys": secrets.token_hex(32),
            "device_cert_sig": secrets.token_hex(64),
            "account_ed_pub": secrets.token_hex(32),
            "identity_key_sig": secrets.token_hex(64),
        }
        a = tc.post(f"/api/keys/link/{code}/approve", json=material, headers=h)
        assert a.status_code == 200, a.text

        # Новое устройство: poll отдаёт аккаунт-материал
        p = tc.get(f"/api/keys/link/poll/{req_id}", headers=h).json()
        assert p["status"] == "approved"
        assert p["device_cert_sig"] == material["device_cert_sig"]
        assert p["account_ed_pub"] == material["account_ed_pub"]
        assert p["identity_key_sig"] == material["identity_key_sig"]


def test_link_backward_compat_no_triple():
    """Старое новое-устройство без тройки: linking по-прежнему работает
    (одобряющий переносит Ed — legacy), поля тройки/cert = None."""
    with TestClient(app, raise_server_exceptions=False) as tc:
        csrf = _register_login(tc)
        h = {"X-CSRF-Token": csrf}
        r = tc.post("/api/keys/link/request",
                    json={"new_device_pub": secrets.token_hex(32)}, headers=h)
        assert r.status_code == 200, r.text
        code = r.json()["link_code"]
        g = tc.get(f"/api/keys/link/{code}", headers=h).json()
        assert g["new_device_x3dh_pub"] is None       # тройки нет
        a = tc.post(f"/api/keys/link/{code}/approve",
                    json={"encrypted_keys": secrets.token_hex(32)}, headers=h)
        assert a.status_code == 200, a.text           # legacy-approve без cert-материала
