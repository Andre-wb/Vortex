"""Разделяемое состояние аутентификации: отзыв доступа и маркер первого фактора.

Списки живут в Rust (`vortex-auth`), Python зовёт их через
`app/security/auth_state_backend.py`. Здесь проверяется контракт, который видят
потребители: выход из сеанса делает выданный токен неприменимым, а маркер
первого фактора одноразовый и не переносится между учётными записями.
"""

import time

from conftest import SyncASGIClient
from fastapi import HTTPException

from app.authentication.password import (
    consume_password_verified,
    has_password_verified,
    mark_password_verified,
)
from app.security.auth_jwt import (
    _is_jti_revoked,
    create_access_token,
    decode_access_token,
    revoke_access_token,
)


class TestAccessRevocation:
    def test_a_revoked_token_no_longer_authenticates(self):
        token = create_access_token(910_001, "+10000000001", "revoked_user")
        assert decode_access_token(token)["sub"] == "910001"

        revoke_access_token(token)

        try:
            decode_access_token(token)
        except HTTPException as refusal:
            assert refusal.status_code == 401
            assert refusal.detail == "Token revoked"
        else:
            raise AssertionError("Отозванный токен всё ещё принимается")

    def test_revoking_one_token_leaves_another_alone(self):
        revoked = create_access_token(910_002, "+10000000002", "revoked_two")
        live = create_access_token(910_003, "+10000000003", "live_three")

        revoke_access_token(revoked)

        assert decode_access_token(live)["sub"] == "910003"

    def test_an_identifier_outside_the_alphabet_is_read_as_revoked(self):
        assert _is_jti_revoked("bad:jti") is True
        assert _is_jti_revoked("../evil") is True
        assert _is_jti_revoked("") is False

    def test_a_token_that_already_expired_is_not_written_anywhere(self):
        from app.security import auth_state_backend

        assert auth_state_backend.revoke_access("expired-jti", time.time() - 1) is False
        assert auth_state_backend.access_revoked("expired-jti") is False

    def test_garbage_is_not_taken_for_a_token(self):
        revoke_access_token("not-a-jwt")


class TestSharedStateUnavailable:
    """Решение владельца: запись без общего состояния отказывает, а не уходит в память."""

    def test_a_logout_that_cannot_record_the_revocation_answers_503(self, monkeypatch):
        from app.security import auth_jwt

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(auth_jwt._auth_state, "revoke_access", refuse)
        token = create_access_token(910_004, "+10000000004", "sealed_user")

        try:
            revoke_access_token(token)
        except HTTPException as refusal:
            assert refusal.status_code == 503
        else:
            raise AssertionError("Отказ записи не был сообщён вызывающему")

    def test_a_login_that_cannot_arm_the_marker_answers_503(self, monkeypatch):
        from app.authentication import password as password_routes

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(password_routes._auth_state, "arm_password_marker", refuse)

        try:
            mark_password_verified(920_007)
        except HTTPException as refusal:
            assert refusal.status_code == 503
        else:
            raise AssertionError("Отказ выдачи маркера не был сообщён вызывающему")

    def test_a_second_factor_that_cannot_burn_the_marker_answers_503(self, monkeypatch):
        from app.authentication import password as password_routes

        def refuse(*_args, **_kwargs):
            raise RuntimeError("общее состояние аутентификации недоступно")

        monkeypatch.setattr(password_routes._auth_state, "burn_password_marker", refuse)

        try:
            consume_password_verified(920_008)
        except HTTPException as refusal:
            assert refusal.status_code == 503
        else:
            raise AssertionError("Отказ сжигания маркера не был сообщён вызывающему")


class TestPasswordMarker:
    def test_the_marker_is_seen_after_the_password_step(self):
        mark_password_verified(920_001)
        assert has_password_verified(920_001) is True

    def test_peeking_does_not_burn_the_marker(self):
        mark_password_verified(920_002)
        assert has_password_verified(920_002) is True
        assert has_password_verified(920_002) is True

    def test_the_second_factor_burns_the_marker(self):
        mark_password_verified(920_003)
        consume_password_verified(920_003)
        assert has_password_verified(920_003) is False

    def test_one_account_never_answers_for_another(self):
        mark_password_verified(920_004)
        assert has_password_verified(920_005) is False

    def test_an_account_nobody_marked_owes_the_password_step(self):
        assert has_password_verified(920_006) is False


class TestLogoutOverHttp:
    def test_the_token_a_session_was_given_dies_with_the_logout(
        self, client: SyncASGIClient, logged_user: dict
    ):
        access = client._cookies.get("access_token")
        assert access, "Вход не выдал access_token"

        bearer = {"Authorization": f"Bearer {access}"}
        before = SyncASGIClient(loop=client._loop)
        assert before.get("/api/authentication/me", headers=bearer).status_code == 200

        assert client.post(
            "/api/authentication/logout", headers=logged_user["headers"]
        ).status_code in (200, 204)

        after = SyncASGIClient(loop=client._loop)
        assert after.get("/api/authentication/me", headers=bearer).status_code == 401
