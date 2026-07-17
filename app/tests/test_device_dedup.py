"""Тесты дедупликации UserDevice по client_device_id.

Стабильный набор устройств для Sesame: сервер переиспользует строку
физического устройства (заголовок X-Device-Id) вместо новой на каждый логин.
"""

import secrets

import pytest

from conftest import random_str, random_digits, _phone_prefix
from app.main import app


def _register(tc, tag):
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    tc.post("/api/authentication/register", json={
        "username":          f"dev_{tag}",
        "password":          "Str0ng_abcd!@",
        "display_name":      f"Dev {tag}",
        "phone":             phone,
        "avatar_emoji":      "\U0001f4f1",
        "x25519_public_key": secrets.token_hex(32),
    })


def _login(tc, tag, device_id=None):
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    headers = {"X-CSRF-Token": csrf}
    if device_id is not None:
        headers["X-Device-Id"] = device_id
    return tc.post("/api/authentication/login", json={
        "phone_or_username": f"dev_{tag}",
        "password":          "Str0ng_abcd!@",
    }, headers=headers)


def _device_count(tc):
    r = tc.get("/api/authentication/devices")
    assert r.status_code == 200, r.text
    return len(r.json().get("devices", r.json()) if isinstance(r.json(), dict) else r.json())


class TestDeviceDedup:

    def test_same_device_id_reuses_row(self):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            tag = random_str(8)
            _register(tc, tag)
            dev = secrets.token_hex(16)
            _login(tc, tag, dev)
            after_first = _device_count(tc)
            # Повторный логин с ТЕМ ЖЕ device_id — строка переиспользуется
            _login(tc, tag, dev)
            _login(tc, tag, dev)
            after_repeat = _device_count(tc)
            assert after_repeat == after_first, "дедуп: та же device_id → та же строка"

    def test_different_device_ids_create_separate_rows(self):
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            tag = random_str(8)
            _register(tc, tag)
            _login(tc, tag, secrets.token_hex(16))
            n1 = _device_count(tc)
            _login(tc, tag, secrets.token_hex(16))   # другое устройство
            n2 = _device_count(tc)
            assert n2 == n1 + 1, "разные device_id → разные строки"

    def test_no_header_falls_back_to_new_row(self):
        """Pre-P2 клиент без заголовка — прежнее поведение (новая строка на логин)."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            tag = random_str(8)
            _register(tc, tag)
            _login(tc, tag, None)
            n1 = _device_count(tc)
            _login(tc, tag, None)
            n2 = _device_count(tc)
            assert n2 == n1 + 1, "без device_id — новая строка каждый логин (backward-compat)"

    def test_garbage_device_id_ignored(self):
        """Мусорный X-Device-Id игнорируется (не крашит, ведёт себя как без него)."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            tag = random_str(8)
            _register(tc, tag)
            r = _login(tc, tag, "not-a-valid-hex-device-id!!")
            assert r.status_code == 200, r.text

    def test_current_device_marked_after_dedup(self):
        """После дедупа текущее устройство корректно помечается is_current."""
        from starlette.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as tc:
            tag = random_str(8)
            _register(tc, tag)
            dev = secrets.token_hex(16)
            _login(tc, tag, dev)
            _login(tc, tag, dev)   # re-login, строка переиспользована + новый refresh
            devices = tc.get("/api/authentication/devices").json()
            devices = devices.get("devices", devices) if isinstance(devices, dict) else devices
            assert any(d.get("is_current") for d in devices), "текущее устройство помечено"
