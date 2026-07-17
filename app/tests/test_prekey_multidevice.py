"""Тесты M1: per-device prekey-бандлы (Sesame).

publish резолвит устройство из заголовка X-Device-Id и апсертит бандл на
(user_id, device_id); GET /{user_id}/devices отдаёт список бандлов активных
устройств; OPK — свои на устройство. Одиночный GET /{user_id} остаётся
обратно-совместимым (primary по updated_at, device_id=NULL для клиента без
стабильного идентификатора устройства).
"""

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from starlette.testclient import TestClient

from conftest import random_str, random_digits, _phone_prefix
from app.config import Config
from app.main import app

_PW = "Str0ng_abcd!@"


def _x25519_pub_hex() -> str:
    return X25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _build_bundle(ik_hex, *, n_opk=3, supports_v2=None):
    """Собирает тело publish-запроса с корректными подписями."""
    ed = Ed25519PrivateKey.generate()
    spk = X25519PrivateKey.generate()
    spk_pub = spk.public_key().public_bytes_raw()
    ik_bytes = bytes.fromhex(ik_hex)
    body = {
        "identity_key":      ik_hex,
        "signed_prekey":     spk_pub.hex(),
        "signed_prekey_sig": ed.sign(spk_pub).hex(),
        "signed_prekey_id":  1,
        "identity_key_ed":   ed.public_key().public_bytes_raw().hex(),
        "identity_key_sig":  ed.sign(ik_bytes).hex(),
        "one_time_prekeys":  [{"key_id": i, "public_key": _x25519_pub_hex()} for i in range(n_opk)],
    }
    if supports_v2 is not None:
        body["supports_v2"] = supports_v2
    return body


@pytest.fixture
def warn_only(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)


def _dev_id() -> str:
    """32-hex client_device_id, как шлёт клиент в X-Device-Id."""
    return secrets.token_hex(16)


def _register(tc) -> tuple[str, str]:
    """Регистрирует пользователя, возвращает (username, x25519_pub_hex)."""
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    ik_hex = _x25519_pub_hex()
    tc.post("/api/authentication/register", json={
        "username":          f"md_{tag}",
        "password":          _PW,
        "display_name":      f"MD {tag}",
        "phone":             phone,
        "avatar_emoji":      "\U0001f511",
        "x25519_public_key": ik_hex,
    })
    return f"md_{tag}", ik_hex


def _login(tc, username, cid=None) -> str:
    """Логинит (создавая/обновляя UserDevice под cid), возвращает csrf."""
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    headers = {"X-CSRF-Token": csrf}
    if cid:
        headers["X-Device-Id"] = cid
    tc.post("/api/authentication/login",
            json={"phone_or_username": username, "password": _PW},
            headers=headers)
    return csrf


def _publish(tc, csrf, ik, cid=None, **kw):
    headers = {"X-CSRF-Token": csrf}
    if cid:
        headers["X-Device-Id"] = cid
    return tc.post("/api/keys/prekeys/publish",
                   json=_build_bundle(ik, **kw), headers=headers)


class TestPerDeviceBundles:

    def test_device_header_binds_bundle_to_device(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            cid = _dev_id()
            csrf = _login(tc, username, cid)
            r = _publish(tc, csrf, ik, cid, supports_v2=True)
            assert r.status_code == 200, r.text

            me = tc.get("/api/authentication/me").json()
            lst = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()
            assert len(lst["bundles"]) == 1
            assert lst["bundles"][0]["device_id"] is not None

    def test_two_devices_two_bundles(self, warn_only):
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            cid_a, cid_b = _dev_id(), _dev_id()

            csrf_a = _login(tc, username, cid_a)
            assert _publish(tc, csrf_a, ik, cid_a, supports_v2=True).status_code == 200
            csrf_b = _login(tc, username, cid_b)
            assert _publish(tc, csrf_b, ik, cid_b, supports_v2=True).status_code == 200

            me = tc.get("/api/authentication/me").json()
            lst = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()
            device_ids = {b["device_id"] for b in lst["bundles"]}
            assert len(lst["bundles"]) == 2
            assert len(device_ids) == 2 and None not in device_ids

    def test_claim_opk_per_device(self, warn_only):
        """M4a: discovery (/devices) OPK НЕ выдаёт; /claim-opk расходует OPK
        СВОЕГО устройства из его пула — ключи разных устройств не пересекаются."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            cid_a, cid_b = _dev_id(), _dev_id()
            csrf_a = _login(tc, username, cid_a)
            _publish(tc, csrf_a, ik, cid_a, n_opk=2, supports_v2=True)
            csrf_b = _login(tc, username, cid_b)
            _publish(tc, csrf_b, ik, cid_b, n_opk=2, supports_v2=True)

            me = tc.get("/api/authentication/me").json()
            uid = me["user_id"]
            h = {"X-CSRF-Token": csrf_b}
            bundles = tc.get(f"/api/keys/prekeys/{uid}/devices").json()["bundles"]
            assert all(b["one_time_prekey"] is None for b in bundles)   # discovery без OPK
            dev_ids = [b["device_id"] for b in bundles]

            # claim по каждому устройству → OPK своего пула, разные ключи
            claims = {}
            for did in dev_ids:
                claims[did] = tc.post(f"/api/keys/prekeys/{uid}/claim-opk", json={"device_id": did}, headers=h).json()["one_time_prekey"]
            assert all(v is not None for v in claims.values())
            assert len(set(claims.values())) == 2

            # Пул устройства = 2 → второй claim отдаёт OPK, третий — нет
            tc.post(f"/api/keys/prekeys/{uid}/claim-opk", json={"device_id": dev_ids[0]}, headers=h)
            third = tc.post(f"/api/keys/prekeys/{uid}/claim-opk", json={"device_id": dev_ids[0]}, headers=h).json()
            assert third["one_time_prekey"] is None

    def test_single_fetch_backward_compatible(self, warn_only):
        """GET /{user_id} без device-заголовка (legacy) — один бандл, работает."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            csrf = _login(tc, username)  # без X-Device-Id
            assert _publish(tc, csrf, ik, supports_v2=True).status_code == 200

            me = tc.get("/api/authentication/me").json()
            single = tc.get(f"/api/keys/prekeys/{me['user_id']}").json()
            assert single["one_time_prekey"] is None    # discovery без OPK (M4a)
            assert single["device_id"] is None
            lst = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()
            assert len(lst["bundles"]) == 1
            assert lst["bundles"][0]["device_id"] is None

    def test_single_fetch_returns_most_recent_device(self, warn_only):
        """После публикации двух устройств /{user_id} отдаёт свежайший бандл."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            cid_a, cid_b = _dev_id(), _dev_id()
            csrf_a = _login(tc, username, cid_a)
            _publish(tc, csrf_a, ik, cid_a, supports_v2=True)
            csrf_b = _login(tc, username, cid_b)
            _publish(tc, csrf_b, ik, cid_b, supports_v2=True)

            me = tc.get("/api/authentication/me").json()
            lst = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"]
            newest = max(b["device_id"] for b in lst)
            single = tc.get(f"/api/keys/prekeys/{me['user_id']}").json()
            assert single["device_id"] == newest

    def test_migrated_null_bundle_lingers_alongside_device_bundle(self, warn_only):
        """Пиннит текущее поведение после prod-миграции: legacy-бандл маппится в
        device_id=NULL, републиш с X-Device-Id заводит ВТОРУЮ строку (device_X),
        а NULL-строка остаётся. GET /devices отдаёт ОБЕ. Дормантно-безвредно
        (нет живого потребителя /devices), но M3 обязан вычистить NULL-фантом
        (см. ADR-002 §3 M1) — этот тест поймает изменение, когда M3 это сделает.
        """
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            cid = _dev_id()
            # 1) legacy-публикация без device-заголовка → device_id=NULL
            csrf0 = _login(tc, username)
            _publish(tc, csrf0, ik, supports_v2=True)
            # 2) тот же аккаунт републишит с X-Device-Id → отдельная device-строка
            csrf1 = _login(tc, username, cid)
            _publish(tc, csrf1, ik, cid, supports_v2=True)

            me = tc.get("/api/authentication/me").json()
            bundles = tc.get(f"/api/keys/prekeys/{me['user_id']}/devices").json()["bundles"]
            device_ids = [b["device_id"] for b in bundles]
            assert len(bundles) == 2
            assert None in device_ids                       # legacy NULL-фантом остаётся
            assert any(d is not None for d in device_ids)   # плюс device-строка
            # Одиночный fetch безопасен — берёт свежайший (не фантом)
            assert tc.get(f"/api/keys/prekeys/{me['user_id']}").json()["device_id"] is not None

    def test_status_is_device_scoped(self, warn_only):
        """status/me отражает СВОЁ устройство: B не считается опубликованным,
        если публиковало только A."""
        with TestClient(app, raise_server_exceptions=False) as tc:
            username, ik = _register(tc)
            cid_a, cid_b = _dev_id(), _dev_id()
            csrf_a = _login(tc, username, cid_a)
            _publish(tc, csrf_a, ik, cid_a, supports_v2=True)
            # Заводим UserDevice для B (логин), но НЕ публикуем его бандл
            _login(tc, username, cid_b)

            st_a = tc.get("/api/keys/prekeys/status/me", headers={"X-Device-Id": cid_a}).json()
            st_b = tc.get("/api/keys/prekeys/status/me", headers={"X-Device-Id": cid_b}).json()
            assert st_a["published"] is True
            assert st_b["published"] is False
