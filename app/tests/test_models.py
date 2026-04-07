"""
Tests for Pydantic validation schemas and SQLAlchemy models.
"""
import secrets
import pytest
from pydantic import ValidationError


class TestRegisterRequestValidation:

    def test_valid_registration(self):
        from app.models import RegisterRequest

        req = RegisterRequest(
            phone="+79001234567",
            username="testuser",
            password="StrongPass99",
            display_name="Test User",
            avatar_emoji="🤖",
            x25519_public_key=secrets.token_hex(32),
        )
        assert req.username == "testuser"

    def test_invalid_phone(self):
        from app.models import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                phone="not-a-phone",
                username="testuser",
                password="StrongPass99",
                x25519_public_key=secrets.token_hex(32),
            )

    def test_invalid_username_special_chars(self):
        from app.models import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                phone="+79001234567",
                username="user@#$%",
                password="StrongPass99",
                x25519_public_key=secrets.token_hex(32),
            )

    def test_username_too_short(self):
        from app.models import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                phone="+79001234567",
                username="ab",
                password="StrongPass99",
                x25519_public_key=secrets.token_hex(32),
            )

    def test_pubkey_wrong_length(self):
        from app.models import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                phone="+79001234567",
                username="testuser",
                password="StrongPass99",
                x25519_public_key="abcd",  # Too short
            )

    def test_pubkey_not_hex(self):
        from app.models import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                phone="+79001234567",
                username="testuser",
                password="StrongPass99",
                x25519_public_key="z" * 64,  # Not valid hex
            )

    def test_email_validation(self):
        from app.models import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                phone="+79001234567",
                username="testuser",
                password="StrongPass99",
                email="not-an-email",
                x25519_public_key=secrets.token_hex(32),
            )

    def test_valid_email(self):
        from app.models import RegisterRequest

        req = RegisterRequest(
            phone="+79001234567",
            username="testuser",
            password="StrongPass99",
            email="user@example.com",
            x25519_public_key=secrets.token_hex(32),
        )
        assert req.email == "user@example.com"

    def test_username_normalized_to_lowercase(self):
        from app.models import RegisterRequest

        req = RegisterRequest(
            phone="+79001234567",
            username="TestUser",
            password="StrongPass99",
            x25519_public_key=secrets.token_hex(32),
        )
        assert req.username == "testuser"


class TestLoginRequestValidation:

    def test_valid_login(self):
        from app.models import LoginRequest

        req = LoginRequest(
            phone_or_username="testuser",
            password="StrongPass99",
        )
        assert req.phone_or_username == "testuser"

    def test_login_empty_password(self):
        from app.models import LoginRequest

        with pytest.raises(ValidationError):
            LoginRequest(
                phone_or_username="testuser",
                password="",
            )


class TestKeyLoginRequestValidation:

    def test_valid_key_login(self):
        from app.models import KeyLoginRequest

        req = KeyLoginRequest(
            challenge_id=secrets.token_hex(16),
            pubkey=secrets.token_hex(32),
            proof=secrets.token_hex(32),
        )
        assert len(req.challenge_id) == 32

    def test_invalid_hex_pubkey(self):
        from app.models import KeyLoginRequest

        with pytest.raises(ValidationError):
            KeyLoginRequest(
                challenge_id=secrets.token_hex(16),
                pubkey="z" * 64,  # Not valid hex
                proof=secrets.token_hex(32),
            )
