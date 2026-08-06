"""M4c: отзыв устройства удаляет его prekey-бандл (revocation под A1).

logout_device (DELETE /devices/{id}) удаляет prekey-бандл + OPK устройства →
сервер перестаёт отдавать его в /devices → отправители исключают из fan-out.
"""

import secrets
from datetime import timedelta

import pytest
from conftest import _phone_prefix, random_digits, random_str
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from starlette.testclient import TestClient

from app.config import Config
from app.main import app

_PW = "Str0ng_abcd!@"


def _x():
    return X25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _bundle(ik):
    ed = Ed25519PrivateKey.generate()
    spk = X25519PrivateKey.generate().public_key().public_bytes_raw()
    return {
        "identity_key": ik,
        "signed_prekey": spk.hex(),
        "signed_prekey_sig": ed.sign(spk).hex(),
        "signed_prekey_id": 1,
        "identity_key_ed": ed.public_key().public_bytes_raw().hex(),
        "identity_key_sig": ed.sign(bytes.fromhex(ik)).hex(),
        "supports_v2": True,
        "one_time_prekeys": [{"key_id": i, "public_key": _x()} for i in range(2)],
    }


@pytest.fixture
def warn_only(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)
    # Убираем 7-дневный порог управления сессиями — тест про отзыв бандла, не про гейт.
    monkeypatch.setattr("app.authentication.session._SESSION_MANAGE_MIN_AGE", timedelta(0))


def _register(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    ik = _x()
    tc.post(
        "/api/authentication/register",
        json={
            "username": f"rv_{tag}",
            "password": _PW,
            "display_name": f"RV {tag}",
            "phone": phone,
            "avatar_emoji": "\U0001f511",
            "x25519_public_key": ik,
        },
    )
    return f"rv_{tag}", ik


def _login(tc, username, cid):
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post(
        "/api/authentication/login",
        json={"phone_or_username": username, "password": _PW},
        headers={"X-CSRF-Token": csrf, "X-Device-Id": cid},
    )
    return csrf


def _publish(tc, csrf, ik, cid):
    tc.post("/api/keys/prekeys/publish", json=_bundle(ik), headers={"X-CSRF-Token": csrf, "X-Device-Id": cid})


def test_logout_device_removes_prekey_bundle(warn_only):
    with TestClient(app, raise_server_exceptions=False) as tc:
        username, ik = _register(tc)
        cid_a, cid_b = secrets.token_hex(16), secrets.token_hex(16)
        csrf_a = _login(tc, username, cid_a)
        _publish(tc, csrf_a, ik, cid_a)
        csrf_b = _login(tc, username, cid_b)
        _publish(tc, csrf_b, ik, cid_b)

        me = tc.get("/api/authentication/me").json()
        before = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"]
        cids_before = {b["client_device_id"] for b in before}
        assert cid_a in cids_before and cid_b in cids_before  # оба устройства в наборе

        # Логинимся снова как A (старейшее устройство → can_manage), находим B
        csrf_a = _login(tc, username, cid_a)
        devices = tc.get("/api/authentication/devices").json()["devices"]
        dev_b = next(d for d in devices if not d["is_current"])

        # Отзываем устройство B
        r = tc.delete(
            f"/api/authentication/devices/{dev_b['id']}", headers={"X-CSRF-Token": csrf_a, "X-Device-Id": cid_a}
        )
        assert r.status_code == 200, r.text

        # Бандл B исчез из fan-out-набора; A остался
        after = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"]
        cids_after = {b["client_device_id"] for b in after}
        assert cid_b not in cids_after  # отозванное устройство исключено
        assert cid_a in cids_after  # оставшееся — на месте
