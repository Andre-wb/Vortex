"""
test_transport_secrets.py — выдача протокольных паролей клиенту.

Покрывает GET /api/transport/level4/secrets:
  - ручка не существует, пока оператор не задал TRANSPORT_ACCESS_TOKEN
  - требуется авторизация пользователя и правильный transport-токен
  - состав ответа: ShadowTLS / Trojan / NaiveProxy, текущие и предыдущие
  - секреты релеев наружу не уходят
  - отдельный rate-limit и отказ на открытом HTTP
"""

from __future__ import annotations

import pytest

from app.config import Config
from app.security import secret_rotation as sr

URL = "/api/transport/level4/secrets"
TOKEN = "test-transport-token-value"  # noqa: S105


@pytest.fixture
def token_enabled(monkeypatch):
    monkeypatch.setattr(Config, "TRANSPORT_ACCESS_TOKEN", TOKEN)
    return TOKEN


@pytest.fixture
def anon_client(client):
    """Клиент без кук: session-scoped фикстура копит их между тестами."""
    saved = dict(client._cookies)
    client._cookies.clear()
    yield client
    client._cookies.clear()
    for name, value in saved.items():
        client._cookies.set(name, value)


class _FakeRequest:
    """Минимальный Request для юнит-проверки транспортной защиты."""

    def __init__(self, scheme: str, client_host: str, headers: dict | None = None):
        self.headers = headers or {}
        self.url = type("_URL", (), {"scheme": scheme})()
        self.client = type("_Client", (), {"host": client_host})()


def _auth(logged_user: dict, token: str | None = TOKEN) -> dict:
    headers = dict(logged_user["headers"])
    if token is not None:
        headers["X-Transport-Token"] = token
    return headers


class TestAccess:
    def test_hidden_without_token_configured(self, client, logged_user):
        """Оператор не задал TRANSPORT_ACCESS_TOKEN — ручки как будто нет."""
        r = client.get(URL, headers=_auth(logged_user))
        assert r.status_code == 404

    def test_requires_login(self, anon_client, token_enabled):
        r = anon_client.get(URL, headers={"X-Transport-Token": TOKEN})
        assert r.status_code == 401

    def test_wrong_token_is_404(self, client, logged_user, token_enabled):
        """Неверный токен не подтверждает существование ручки."""
        r = client.get(URL, headers=_auth(logged_user, "wrong-token"))
        assert r.status_code == 404

    def test_missing_token_header(self, client, logged_user, token_enabled):
        r = client.get(URL, headers=_auth(logged_user, None))
        assert r.status_code == 404

    def test_valid_token(self, client, logged_user, token_enabled):
        r = client.get(URL, headers=_auth(logged_user))
        assert r.status_code == 200

    def test_non_ascii_token_is_404(self, client, logged_user, token_enabled):
        """Не-ASCII в заголовке — отказ, а не 500 (иначе это оракул наличия ручки)."""
        headers = _auth(logged_user, None)
        headers["X-Transport-Token"] = b"\xff\xfe-token"
        r = client.get(URL, headers=headers)
        assert r.status_code == 404


class TestPayload:
    def test_contains_current_protocol_passwords(self, client, logged_user, token_enabled):
        body = client.get(URL, headers=_auth(logged_user)).json()
        assert body["shadowtls"]["password"] == Config.SHADOWTLS_PASSWORD
        assert body["trojan"]["password"] == Config.TROJAN_PASSWORD
        assert body["naiveproxy"]["username"] == Config.NAIVE_USERNAME
        assert body["naiveproxy"]["probe_domain"] == Config.NAIVE_PROBE_DOMAIN
        assert body["naiveproxy"]["password"]

    def test_no_default_literals(self, client, logged_user, token_enabled):
        """В ответе не должно быть предсказуемых значений из репозитория."""
        raw = client.get(URL, headers=_auth(logged_user)).text
        for literal in ("vortex-stls", "vortex-trojan", '"vortex"', "unsplash.com"):
            assert literal not in raw

    def test_relay_secrets_not_exposed(self, client, logged_user, token_enabled):
        """К релеям ходит сервер — клиенту их секреты не нужны."""
        raw = client.get(URL, headers=_auth(logged_user)).text
        for secret in (Config.CDN_WORKER_KV_SECRET, Config.AWS_RELAY_SECRET, Config.AZURE_RELAY_SECRET):
            assert secret not in raw

    def test_next_rotation_present(self, client, logged_user, token_enabled):
        body = client.get(URL, headers=_auth(logged_user)).json()
        assert body["next_rotation"] == sr.rotation_status()["next_rotation"]

    def test_previous_values_after_rotation(self, client, logged_user, token_enabled, monkeypatch):
        """После ротации клиент видит и новое значение, и прежнее (grace)."""
        import os

        monkeypatch.setattr(Config, "SHADOWTLS_PASSWORD", "shadow-new")
        monkeypatch.setattr(Config, "TROJAN_PASSWORD", "trojan-new")
        monkeypatch.setitem(os.environ, "SHADOWTLS_PASSWORD_PREV", "shadow-old")
        monkeypatch.setitem(os.environ, "TROJAN_PASSWORD_PREV", "trojan-old")

        body = client.get(URL, headers=_auth(logged_user)).json()
        assert body["shadowtls"] == {"password": "shadow-new", "previous_password": "shadow-old"}
        assert body["trojan"] == {"password": "trojan-new", "previous_password": "trojan-old"}

    def test_previous_is_null_before_first_rotation(self, client, logged_user, token_enabled, monkeypatch):
        import os

        monkeypatch.delitem(os.environ, "SHADOWTLS_PASSWORD_PREV", raising=False)
        body = client.get(URL, headers=_auth(logged_user)).json()
        assert body["shadowtls"]["previous_password"] is None


class TestRotationGrace:
    """rotate_all под моками: в .env не пишем, Config восстанавливаем сами."""

    def test_rotation_moves_current_to_previous(self, monkeypatch):
        import os

        from app.transport.stealth_level4 import stealth_l4

        saved = {k: getattr(Config, k) for k in sr.ROTATABLE}
        saved_env = {k: os.environ.get(k) for k in sr.ROTATABLE}
        saved_prev = {k: os.environ.get(k + sr.PREV_SUFFIX) for k in sr.ROTATABLE}

        written: dict[str, str] = {}

        def fake_upsert(key: str, value: str) -> None:
            written[key] = value
            os.environ[key] = value

        monkeypatch.setattr(sr, "env_upsert", fake_upsert)
        monkeypatch.setattr(sr, "is_externally_set", lambda key: False)
        try:
            rotated = sr.rotate_all()
            assert set(rotated) == set(sr.ROTATABLE)
            assert written["SHADOWTLS_PASSWORD"] == Config.SHADOWTLS_PASSWORD
            assert written["SHADOWTLS_PASSWORD_PREV"] == saved["SHADOWTLS_PASSWORD"]
            assert saved["SHADOWTLS_PASSWORD"] != Config.SHADOWTLS_PASSWORD
            # Живые объекты подхватили новое значение и держат прежнее.
            assert stealth_l4.shadowtls._password.decode() == Config.SHADOWTLS_PASSWORD
            assert stealth_l4.shadowtls._prev_hmac_key
        finally:
            for key, value in saved.items():
                setattr(Config, key, value)
            for key, value in {**saved_env, **{k + sr.PREV_SUFFIX: v for k, v in saved_prev.items()}}.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            stealth_l4.reload_secrets()

    def test_externally_set_secrets_are_skipped(self, monkeypatch):
        monkeypatch.setattr(sr, "env_upsert", lambda key, value: None)
        monkeypatch.setattr(sr, "is_externally_set", lambda key: True)
        assert sr.rotate_all() == []


class TestHardening:
    def test_rate_limited(self, client, logged_user, token_enabled, monkeypatch):
        from app.transport import pluggable_routes as pr

        monkeypatch.setattr(Config, "TRANSPORT_SECRETS_RATE_LIMIT", 3)
        monkeypatch.setattr(pr, "_secrets_rate", {})
        codes = [client.get(URL, headers=_auth(logged_user)).status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200]
        assert codes[3:] == [429, 429]

    def test_plain_http_rejected(self, monkeypatch):
        """Вне тестового режима пароли по открытому HTTP не отдаются."""
        from app.transport.pluggable_routes import _is_secure_request

        monkeypatch.setattr(Config, "TESTING", False)
        assert _is_secure_request(_FakeRequest("http", "203.0.113.7")) is False
        assert _is_secure_request(_FakeRequest("https", "203.0.113.7")) is True
        # Локальные вызовы (клиент на той же машине) остаются разрешёнными.
        assert _is_secure_request(_FakeRequest("http", "127.0.0.1")) is True
        # Заголовок от TLS-терминатора важнее схемы внутреннего запроса.
        assert _is_secure_request(_FakeRequest("http", "203.0.113.7", {"x-forwarded-proto": "https,http"})) is True
        assert _is_secure_request(_FakeRequest("https", "203.0.113.7", {"x-forwarded-proto": "http"})) is False

    def test_https_via_forwarded_proto(self, client, logged_user, token_enabled, monkeypatch):
        """За TLS-терминатором признаётся X-Forwarded-Proto."""
        from app.transport import pluggable_routes as pr

        monkeypatch.setattr(Config, "TESTING", False)
        monkeypatch.setattr(pr, "_secrets_rate", {})
        headers = _auth(logged_user)
        headers["X-Forwarded-Proto"] = "https"
        r = client.get(URL, headers=headers)
        assert r.status_code == 200
