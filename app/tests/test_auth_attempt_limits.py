"""Счёт попыток аутентификации в общем состоянии (крейт `vortex-auth`).

Скользящее окно попыток входа, регистрации и второго фактора живёт в Rust и
одинаково для всех воркеров. Здесь проверяется контракт, который видят
потребители: предел общий на адрес клиента, вход и регистрация считаются в одном
окне, учётные записи не тратят попытки друг друга, а попытка, которую некому
сосчитать, отклоняется, а не пропускается.
"""

import secrets

import pytest

from app.authentication import _helpers, key_login
from app.security import auth_state_backend as _auth_state


def address() -> str:
    return f"198.51.100.{secrets.token_hex(6)}"


def account() -> int:
    return 900_000_000 + secrets.randbelow(100_000_000)


class TestEntryAttempts:
    def test_ten_logins_from_one_address_pass_and_the_eleventh_does_not(self):
        client = address()
        for _ in range(10):
            assert _auth_state.entry_login_allowed(client) is True
        assert _auth_state.entry_login_allowed(client) is False

    def test_five_registrations_from_one_address_pass_and_the_sixth_does_not(self):
        client = address()
        for _ in range(5):
            assert _auth_state.entry_register_allowed(client) is True
        assert _auth_state.entry_register_allowed(client) is False

    def test_logins_and_registrations_share_one_window_per_address(self):
        client = address()
        for _ in range(5):
            assert _auth_state.entry_register_allowed(client) is True
        for _ in range(5):
            assert _auth_state.entry_login_allowed(client) is True
        assert _auth_state.entry_login_allowed(client) is False

    def test_one_noisy_address_never_locks_out_another(self):
        noisy = address()
        quiet = address()
        for _ in range(10):
            _auth_state.entry_login_allowed(noisy)
        assert _auth_state.entry_login_allowed(noisy) is False
        assert _auth_state.entry_login_allowed(quiet) is True

    def test_every_shape_a_socket_hands_over_is_counted(self):
        for client in ["127.0.0.1", "fe80::1%lo0", "unknown"]:
            assert _auth_state.entry_login_allowed(f"{client}-{secrets.token_hex(4)}") is True

    def test_an_address_that_no_socket_could_produce_is_refused(self):
        for hostile in ["", "10.0.0.1 ", "10.0.0.1\n", "a" * 65]:
            with pytest.raises(ValueError):
                _auth_state.entry_login_allowed(hostile)


class TestSecondFactorAttempts:
    def test_five_tries_at_the_code_pass_and_the_sixth_does_not(self):
        user = account()
        for _ in range(5):
            assert _auth_state.totp_attempt_allowed(user) is True
        assert _auth_state.totp_attempt_allowed(user) is False

    def test_one_account_never_spends_the_tries_of_another(self):
        noisy = account()
        quiet = noisy + 1
        for _ in range(5):
            _auth_state.totp_attempt_allowed(noisy)
        assert _auth_state.totp_attempt_allowed(noisy) is False
        assert _auth_state.totp_attempt_allowed(quiet) is True

    def test_a_number_that_names_no_account_is_refused(self):
        for absent in [0, -1]:
            with pytest.raises(ValueError):
                _auth_state.totp_attempt_allowed(absent)

    def test_the_entry_window_and_the_code_window_never_share_a_count(self):
        user = account()
        for _ in range(5):
            _auth_state.totp_attempt_allowed(user)
        assert _auth_state.totp_attempt_allowed(user) is False
        assert _auth_state.entry_login_allowed(str(user)) is True


class TestOverHttp:
    """Роут считает попытки только вне TESTING — иначе ограничитель выключен."""

    def _attempt(self, client) -> int:
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        return client.post(
            "/api/authentication/login-key",
            json={
                "challenge_id": "0" * 32,
                "pubkey": "ab" * 32,
                "proof": "cd" * 32,
            },
            headers={"X-CSRF-Token": csrf},
        ).status_code

    def test_the_eleventh_login_from_one_client_answers_429(self, client, monkeypatch):
        client_address = address()
        monkeypatch.setattr(_helpers, "_IS_TESTING", False)
        monkeypatch.setattr(key_login, "raw_ip_for_ratelimit", lambda _request: client_address)

        for _ in range(10):
            assert self._attempt(client) == 401
        assert self._attempt(client) == 429

    def test_a_client_the_shared_state_cannot_count_is_refused(self, client, monkeypatch):
        monkeypatch.setattr(_helpers, "_IS_TESTING", False)
        monkeypatch.setattr(_helpers._auth_state, "entry_login_allowed", lambda _client: False)

        assert self._attempt(client) == 429

    def test_the_limiter_is_off_while_testing(self, client):
        for _ in range(12):
            assert self._attempt(client) == 401
