"""Тесты публикации prekey-бандлов и серверной верификации подписей.

Проверяют verify_spk_signature (первое живое использование
double_ratchet.py), режимы warn-only/enforce, cross-signature identity_key_sig,
хранение Ed25519-ключа и расход one-time prekeys.
"""


import pytest
from conftest import _phone_prefix, random_digits, random_str
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.config import Config
from app.main import app


def _x25519_pub_hex() -> str:
    return X25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _register_and_login(tc):
    """Регистрирует пользователя, логинит, возвращает (csrf, x25519_pub_hex)."""
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    ik_hex = _x25519_pub_hex()
    tc.post("/api/authentication/register", json={
        "username":          f"pk_{tag}",
        "password":          "Str0ng_abcd!@",
        "display_name":      f"PK {tag}",
        "phone":             phone,
        "avatar_emoji":      "\U0001f511",
        "x25519_public_key": ik_hex,
    })
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post("/api/authentication/login", json={
        "phone_or_username": f"pk_{tag}",
        "password":          "Str0ng_abcd!@",
    }, headers={"X-CSRF-Token": csrf})
    return csrf, ik_hex


def _build_bundle(ik_hex, *, ed_priv=None, spk_priv=None, bad_spk_sig=False,
                  bad_id_sig=False, omit_ed=False, omit_id_sig=False, n_opk=3,
                  supports_v2=None):
    """Собирает тело publish-запроса с корректными или намеренно битыми подписями."""
    ed = ed_priv or Ed25519PrivateKey.generate()
    spk = spk_priv or X25519PrivateKey.generate()
    spk_pub = spk.public_key().public_bytes_raw()
    ik_bytes = bytes.fromhex(ik_hex)

    spk_sig = ed.sign(spk_pub)
    id_sig = ed.sign(ik_bytes)
    if bad_spk_sig:
        spk_sig = bytes([spk_sig[0] ^ 0xFF]) + spk_sig[1:]
    if bad_id_sig:
        id_sig = bytes([id_sig[0] ^ 0xFF]) + id_sig[1:]

    body = {
        "identity_key":      ik_hex,
        "signed_prekey":     spk_pub.hex(),
        "signed_prekey_sig": spk_sig.hex(),
        "signed_prekey_id":  1,
        "one_time_prekeys":  [{"key_id": i, "public_key": _x25519_pub_hex()} for i in range(n_opk)],
    }
    if not omit_ed:
        body["identity_key_ed"] = ed.public_key().public_bytes_raw().hex()
    if not omit_id_sig:
        body["identity_key_sig"] = id_sig.hex()
    if supports_v2 is not None:
        body["supports_v2"] = supports_v2
    return body


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", True)


@pytest.fixture
def warn_only(monkeypatch):
    monkeypatch.setattr(Config, "PREKEY_SIG_ENFORCE", False)


class TestPublishValid:

    def test_valid_bundle_accepted(self, warn_only):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["published"] is True
            assert body["available_opk_count"] == 3

    def test_valid_bundle_accepted_in_enforce(self, enforce):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 200, r.text

    def test_ed_key_stored_and_returned_in_bundle(self, warn_only):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            bundle = _build_bundle(ik)
            tc.post("/api/keys/prekeys/publish", json=bundle, headers={"X-CSRF-Token": csrf})

            me = tc.get("/api/authentication/me").json()
            r = tc.get(f"/api/keys/prekeys/{me['user_id']}")
            assert r.status_code == 200, r.text
            fetched = r.json()
            assert fetched["identity_key_ed"] == bundle["identity_key_ed"]
            assert fetched["identity_key_sig"] == bundle["identity_key_sig"]
            assert fetched["one_time_prekey"] is None  # discovery не выдаёт OPK (M4a)


class TestEnforceRejects:

    def test_bad_spk_sig_rejected(self, enforce):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle(ik, bad_spk_sig=True),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 400

    def test_bad_identity_binding_sig_rejected(self, enforce):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle(ik, bad_id_sig=True),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 400

    def test_missing_ed_key_rejected(self, enforce):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle(ik, omit_ed=True, omit_id_sig=True),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 400

    def test_rejected_bundle_not_persisted(self, enforce):
        """Отклонённый в enforce бандл не должен частично записаться в БД."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            tc.post("/api/keys/prekeys/publish",
                    json=_build_bundle(ik, bad_spk_sig=True),
                    headers={"X-CSRF-Token": csrf})
            status = tc.get("/api/keys/prekeys/status/me").json()
            assert status["published"] is False


class TestWarnOnly:

    def test_bad_sig_accepted_and_stored_in_warn_mode(self, warn_only):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle(ik, bad_spk_sig=True),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 200, r.text
            assert tc.get("/api/keys/prekeys/status/me").json()["published"] is True

    def test_legacy_client_without_ed_accepted_in_warn(self, warn_only):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            r = tc.post("/api/keys/prekeys/publish",
                        json=_build_bundle(ik, omit_ed=True, omit_id_sig=True),
                        headers={"X-CSRF-Token": csrf})
            assert r.status_code == 200, r.text


class TestSupportsV2Capability:
    """Capability-флаг supports_v2 хранится и отдаётся в
    fetch/status, чтобы отправитель знал, можно ли слать адресату v2."""

    def test_supports_v2_stored_and_returned(self, warn_only):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik, supports_v2=True),
                    headers={"X-CSRF-Token": csrf})
            me = tc.get("/api/authentication/me").json()

            fetched = tc.get(f"/api/keys/prekeys/{me['user_id']}").json()
            assert fetched["supports_v2"] is True

            status = tc.get("/api/keys/prekeys/status/me").json()
            assert status["supports_v2"] is True

    def test_legacy_bundle_without_supports_v2_is_null(self, warn_only):
        """Пред-6b бандл (без supports_v2) → null: отправитель не шлёт v2."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik),  # без supports_v2
                    headers={"X-CSRF-Token": csrf})
            status = tc.get("/api/keys/prekeys/status/me").json()
            assert status["supports_v2"] in (None, False)

    def test_republish_flips_supports_v2(self, warn_only):
        """republish с supports_v2=True обновляет ранее опубликованный бандл."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik),
                    headers={"X-CSRF-Token": csrf})
            assert tc.get("/api/keys/prekeys/status/me").json()["supports_v2"] in (None, False)
            tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik, supports_v2=True),
                    headers={"X-CSRF-Token": csrf})
            assert tc.get("/api/keys/prekeys/status/me").json()["supports_v2"] is True


class TestOpkConsumption:

    def test_opk_consumed_via_claim_not_discovery(self, warn_only):
        """M4a: discovery (GET) OPK НЕ расходует; расход — только через /claim-opk."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            csrf, ik = _register_and_login(tc)
            tc.post("/api/keys/prekeys/publish", json=_build_bundle(ik, n_opk=2),
                    headers={"X-CSRF-Token": csrf})
            uid = tc.get("/api/authentication/me").json()["user_id"]
            h = {"X-CSRF-Token": csrf}

            # Discovery не расходует — сколько ни фетчь, OPK не выдаётся
            assert tc.get(f"/api/keys/prekeys/{uid}").json()["one_time_prekey"] is None
            assert tc.get(f"/api/keys/prekeys/{uid}").json()["one_time_prekey"] is None

            # claim-opk расходует по одному (device_id=None — публикация без X-Device-Id)
            first = tc.post(f"/api/keys/prekeys/{uid}/claim-opk", json={"device_id": None}, headers=h).json()
            second = tc.post(f"/api/keys/prekeys/{uid}/claim-opk", json={"device_id": None}, headers=h).json()
            assert first["one_time_prekey"] is not None
            assert second["one_time_prekey"] is not None
            assert first["one_time_prekey"] != second["one_time_prekey"]

            # Пул иссяк — третий claim без OPK
            third = tc.post(f"/api/keys/prekeys/{uid}/claim-opk", json={"device_id": None}, headers=h).json()
            assert third["one_time_prekey"] is None
