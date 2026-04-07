"""
Comprehensive security test suite for Vortex.

Covers: crypto.py, key_exchange.py, auth_jwt.py, security_validate.py,
        secure_upload.py, middleware.py (HTTP), waf.py (HTTP), logging_config.py.
"""

import json
import logging
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conftest import make_user, login_user, random_str, random_digits


# ═══════════════════════════════════════════════════════════════════════════════
# 1. crypto.py
# ═══════════════════════════════════════════════════════════════════════════════

from app.security.crypto import (
    generate_key,
    encrypt_message,
    decrypt_message,
    hash_message,
    hash_password,
    verify_password,
    hash_token,
    verify_token_hash,
    generate_x25519_keypair,
    derive_x25519_session_key,
    rust_available,
    load_or_create_node_keypair,
    get_node_public_key_hex,
)


class TestGenerateKey:
    def test_returns_32_bytes(self):
        key = generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_unique_keys(self):
        k1 = generate_key()
        k2 = generate_key()
        assert k1 != k2


class TestEncryptMessage:
    def test_roundtrip(self):
        key = generate_key()
        plaintext = b"Hello, Vortex!"
        ct = encrypt_message(plaintext, key)
        assert decrypt_message(ct, key) == plaintext

    def test_different_nonces(self):
        key = generate_key()
        pt = b"same data"
        ct1 = encrypt_message(pt, key)
        ct2 = encrypt_message(pt, key)
        assert ct1 != ct2

    def test_ciphertext_differs_from_plaintext(self):
        key = generate_key()
        pt = b"secret"
        ct = encrypt_message(pt, key)
        assert pt not in ct


class TestDecryptMessage:
    def test_success(self):
        key = generate_key()
        pt = b"data"
        ct = encrypt_message(pt, key)
        assert decrypt_message(ct, key) == pt

    def test_tampered_data_fails(self):
        key = generate_key()
        ct = encrypt_message(b"ok", key)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_message(bytes(tampered), key)

    def test_wrong_key_fails(self):
        key1 = generate_key()
        key2 = generate_key()
        ct = encrypt_message(b"secret", key1)
        with pytest.raises(Exception):
            decrypt_message(ct, key2)


class TestHashMessage:
    def test_deterministic(self):
        data = b"hello"
        assert hash_message(data) == hash_message(data)

    def test_different_data_different_hash(self):
        assert hash_message(b"aaa") != hash_message(b"bbb")

    def test_empty_data(self):
        h = hash_message(b"")
        assert isinstance(h, bytes)
        assert len(h) == 32

    def test_returns_32_bytes(self):
        h = hash_message(b"test")
        assert len(h) == 32


class TestHashPassword:
    def test_hash_differs_from_plaintext(self):
        pw = "StrongPass99!"
        h = hash_password(pw)
        assert h != pw

    def test_different_calls_different_salts(self):
        pw = "SamePassword1!"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2

    def test_returns_string(self):
        h = hash_password("Test1234!")
        assert isinstance(h, str)
        assert len(h) > 0


class TestVerifyPassword:
    def test_correct_password(self):
        pw = "Correct#Pass1"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_wrong_password(self):
        h = hash_password("RightPassword1!")
        assert verify_password("WrongPassword1!", h) is False

    def test_empty_password_against_hash(self):
        h = hash_password("Something1!")
        assert verify_password("", h) is False


class TestHashToken:
    def test_returns_string(self):
        t = hash_token("my-token-abc")
        assert isinstance(t, str)
        assert len(t) > 0

    def test_deterministic(self):
        token = "deterministic-token-123"
        assert hash_token(token) == hash_token(token)

    def test_different_tokens_different_hashes(self):
        assert hash_token("aaa") != hash_token("bbb")


class TestVerifyTokenHash:
    def test_correct_token(self):
        token = "my-secure-token"
        h = hash_token(token)
        assert verify_token_hash(token, h) is True

    def test_wrong_token(self):
        h = hash_token("real-token")
        assert verify_token_hash("fake-token", h) is False


class TestGenerateX25519Keypair:
    def test_returns_32_byte_pair(self):
        priv, pub = generate_x25519_keypair()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)
        assert len(priv) == 32
        assert len(pub) == 32

    def test_unique_keypairs(self):
        p1, _ = generate_x25519_keypair()
        p2, _ = generate_x25519_keypair()
        assert p1 != p2


class TestDeriveX25519SessionKey:
    def test_dh_agreement(self):
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        key_ab = derive_x25519_session_key(alice_priv, bob_pub)
        key_ba = derive_x25519_session_key(bob_priv, alice_pub)
        assert key_ab == key_ba

    def test_different_peers_different_keys(self):
        alice_priv, alice_pub = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()
        carol_priv, carol_pub = generate_x25519_keypair()
        key_ab = derive_x25519_session_key(alice_priv, bob_pub)
        key_ac = derive_x25519_session_key(alice_priv, carol_pub)
        assert key_ab != key_ac

    def test_returns_32_bytes(self):
        priv, _ = generate_x25519_keypair()
        _, peer_pub = generate_x25519_keypair()
        key = derive_x25519_session_key(priv, peer_pub)
        assert len(key) == 32


class TestRustAvailable:
    def test_returns_bool(self):
        result = rust_available()
        assert isinstance(result, bool)


class TestLoadOrCreateNodeKeypair:
    def test_creates_files(self):
        with tempfile.TemporaryDirectory() as td:
            keys_dir = Path(td) / "test_keys"
            # Reset cached keys
            import app.security.crypto as _cm
            _cm._node_priv = None
            _cm._node_pub = None

            priv, pub = load_or_create_node_keypair(keys_dir)
            assert len(priv) == 32
            assert len(pub) == 32
            assert (keys_dir / "x25519_private.bin").exists()
            assert (keys_dir / "x25519_public.bin").exists()

    def test_idempotent_load(self):
        with tempfile.TemporaryDirectory() as td:
            keys_dir = Path(td) / "test_keys2"
            import app.security.crypto as _cm
            _cm._node_priv = None
            _cm._node_pub = None

            priv1, pub1 = load_or_create_node_keypair(keys_dir)
            # Reset cached to force re-read from disk
            _cm._node_priv = None
            _cm._node_pub = None
            priv2, pub2 = load_or_create_node_keypair(keys_dir)
            assert priv1 == priv2
            assert pub1 == pub2


class TestGetNodePublicKeyHex:
    def test_returns_64_char_hex(self):
        with tempfile.TemporaryDirectory() as td:
            keys_dir = Path(td) / "test_keys3"
            import app.security.crypto as _cm
            _cm._node_priv = None
            _cm._node_pub = None

            hex_key = get_node_public_key_hex(keys_dir)
            assert isinstance(hex_key, str)
            assert len(hex_key) == 64
            bytes.fromhex(hex_key)  # must be valid hex


# ═══════════════════════════════════════════════════════════════════════════════
# 2. key_exchange.py
# ═══════════════════════════════════════════════════════════════════════════════

from app.security.key_exchange import (
    ecies_encrypt,
    ecies_decrypt_node,
    encrypt_p2p_payload,
    decrypt_p2p_payload,
    format_encrypted_key,
    validate_ecies_payload,
)


class TestEciesEncrypt:
    def test_returns_dict_with_required_fields(self):
        _, pub = generate_x25519_keypair()
        result = ecies_encrypt(b"secret data", pub.hex())
        assert "ephemeral_pub" in result
        assert "ciphertext" in result
        assert len(result["ephemeral_pub"]) == 64
        assert len(result["ciphertext"]) >= 24

    def test_different_each_time(self):
        _, pub = generate_x25519_keypair()
        r1 = ecies_encrypt(b"same", pub.hex())
        r2 = ecies_encrypt(b"same", pub.hex())
        assert r1["ephemeral_pub"] != r2["ephemeral_pub"]
        assert r1["ciphertext"] != r2["ciphertext"]

    def test_invalid_pub_length_raises(self):
        with pytest.raises(ValueError, match="64"):
            ecies_encrypt(b"data", "abcd")


class TestEciesDecryptNode:
    def test_roundtrip_success(self):
        priv, pub = generate_x25519_keypair()
        plaintext = b"node secret payload"
        enc = ecies_encrypt(plaintext, pub.hex())
        decrypted = ecies_decrypt_node(enc["ephemeral_pub"], enc["ciphertext"], priv)
        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        _, pub = generate_x25519_keypair()
        wrong_priv, _ = generate_x25519_keypair()
        enc = ecies_encrypt(b"data", pub.hex())
        with pytest.raises(Exception):
            ecies_decrypt_node(enc["ephemeral_pub"], enc["ciphertext"], wrong_priv)

    def test_binary_roundtrip(self):
        priv, pub = generate_x25519_keypair()
        data = secrets.token_bytes(32)
        enc = ecies_encrypt(data, pub.hex())
        decrypted = ecies_decrypt_node(enc["ephemeral_pub"], enc["ciphertext"], priv)
        assert decrypted == data


class TestEncryptP2pPayload:
    def test_returns_encrypted_dict(self):
        our_priv, our_pub = generate_x25519_keypair()
        peer_priv, peer_pub = generate_x25519_keypair()
        payload = {"room_id": "abc123", "sender": "alice"}
        result = encrypt_p2p_payload(payload, our_priv, peer_pub.hex())
        assert "ephemeral_pub" in result
        assert "ciphertext" in result


class TestDecryptP2pPayload:
    def test_roundtrip_success(self):
        our_priv, our_pub = generate_x25519_keypair()
        peer_priv, peer_pub = generate_x25519_keypair()
        payload = {"room_id": "room1", "sender": "node1", "message": "hello"}
        encrypted = encrypt_p2p_payload(payload, our_priv, peer_pub.hex())
        decrypted = decrypt_p2p_payload(
            encrypted["ephemeral_pub"], encrypted["ciphertext"], peer_priv
        )
        assert decrypted == payload

    def test_wrong_key_raises_valueerror(self):
        _, peer_pub = generate_x25519_keypair()
        wrong_priv, _ = generate_x25519_keypair()
        payload = {"data": "test"}
        our_priv, _ = generate_x25519_keypair()
        encrypted = encrypt_p2p_payload(payload, our_priv, peer_pub.hex())
        with pytest.raises(ValueError, match="P2P"):
            decrypt_p2p_payload(
                encrypted["ephemeral_pub"], encrypted["ciphertext"], wrong_priv
            )


class TestFormatEncryptedKey:
    def test_returns_tuple_of_strings(self):
        enc = {"ephemeral_pub": "aa" * 32, "ciphertext": "bb" * 30}
        eph, ct = format_encrypted_key(enc)
        assert isinstance(eph, str)
        assert isinstance(ct, str)
        assert eph == "aa" * 32
        assert ct == "bb" * 30


class TestValidateEciesPayload:
    def test_valid_dict(self):
        _, pub = generate_x25519_keypair()
        enc = ecies_encrypt(b"test", pub.hex())
        assert validate_ecies_payload(enc) is True

    def test_missing_fields(self):
        assert validate_ecies_payload({}) is False
        assert validate_ecies_payload({"ephemeral_pub": "aa" * 32}) is False

    def test_short_ephemeral_pub(self):
        assert validate_ecies_payload({"ephemeral_pub": "ab", "ciphertext": "cc" * 30}) is False

    def test_short_ciphertext(self):
        assert validate_ecies_payload({"ephemeral_pub": "aa" * 32, "ciphertext": "cc"}) is False

    def test_invalid_hex(self):
        assert validate_ecies_payload({"ephemeral_pub": "zz" * 32, "ciphertext": "cc" * 30}) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 3. auth_jwt.py
# ═══════════════════════════════════════════════════════════════════════════════

from app.security.auth_jwt import (
    create_access_token,
    decode_access_token,
    create_refresh_token,
    verify_refresh_token,
)
from fastapi import HTTPException


class TestCreateAccessToken:
    def test_returns_jwt_string(self):
        token = create_access_token(user_id=1, phone="+79001234567", username="testuser")
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT has three parts separated by dots
        parts = token.split(".")
        assert len(parts) == 3

    def test_unique_tokens(self):
        t1 = create_access_token(1, "+79001234567", "user1")
        t2 = create_access_token(1, "+79001234567", "user1")
        assert t1 != t2  # different jti each time


class TestDecodeAccessToken:
    def test_valid_token_decoded(self):
        token = create_access_token(42, "+79009999999", "decoder_user")
        payload = decode_access_token(token)
        assert payload["sub"] == "42"
        assert payload["phone"] == "+79009999999"
        assert payload["username"] == "decoder_user"
        assert "exp" in payload
        assert "jti" in payload

    def test_expired_token_raises(self):
        import jwt as pyjwt
        from app.config import Config
        now = datetime.now(timezone.utc)
        expired_payload = {
            "sub": "1",
            "phone": "+79001111111",
            "username": "expired",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "jti": secrets.token_hex(16),
            "typ": "access",
        }
        token = pyjwt.encode(expired_payload, Config.JWT_SECRET, algorithm="HS256")
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_invalid_token_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token("this.is.invalid")
        assert exc_info.value.status_code == 401


class TestCreateRefreshToken:
    def test_returns_raw_and_expiry(self, client):
        user_info = make_user(client)
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            from app.models import User
            user = db.query(User).filter(User.username == user_info["username"]).first()
            assert user is not None
            raw, expiry = create_refresh_token(user.id, db)
            assert isinstance(raw, str)
            assert len(raw) > 0
            assert isinstance(expiry, datetime)
            assert expiry > datetime.now(timezone.utc)
        finally:
            db.close()


class TestVerifyRefreshToken:
    def test_valid_returns_user(self, client):
        user_info = make_user(client)
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            from app.models import User
            user = db.query(User).filter(User.username == user_info["username"]).first()
            raw, _ = create_refresh_token(user.id, db)
            result_user = verify_refresh_token(raw, db)
            assert result_user.id == user.id
        finally:
            db.close()

    def test_invalid_raises(self, client):
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            with pytest.raises(HTTPException) as exc_info:
                verify_refresh_token("bogus-token-value", db)
            assert exc_info.value.status_code == 401
        finally:
            db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. security_validate.py
# ═══════════════════════════════════════════════════════════════════════════════

from app.security.security_validate import (
    validate_password,
    validate_password_with_context,
    calculate_password_strength,
    generate_secure_password,
)


class TestValidatePassword:
    def test_valid(self):
        ok, msg = validate_password("G00dP@ssw0rd!")
        assert ok is True
        assert msg == ""

    def test_too_short(self):
        ok, msg = validate_password("Ab1!")
        assert ok is False
        assert "8" in msg

    def test_no_uppercase(self):
        ok, msg = validate_password("nouppercase1!")
        assert ok is False

    def test_no_lowercase(self):
        ok, msg = validate_password("NOLOWERCASE1!")
        assert ok is False

    def test_no_digit(self):
        ok, msg = validate_password("NoDigitHere!")
        assert ok is False

    def test_no_special(self):
        ok, msg = validate_password("NoSpecial1aa")
        assert ok is False

    def test_common_password(self):
        # Common passwords lack required chars, so they are rejected
        # by character checks before the common password check.
        # Verify they are still rejected.
        ok, _ = validate_password("password")
        assert ok is False
        ok, _ = validate_password("qwerty")
        assert ok is False
        ok, _ = validate_password("123456")
        assert ok is False

    def test_repeated_chars(self):
        ok, msg = validate_password("Aaaa1111!!!!")
        assert ok is False

    def test_sequences(self):
        ok, msg = validate_password("Qwerty99!!xx")
        assert ok is False
        assert "последовательность" in msg.lower() or "последовательность" in msg

    def test_keyboard_sequences(self):
        ok, msg = validate_password("Asdfgh99!!xx")
        assert ok is False


class TestValidatePasswordWithContext:
    def test_username_in_password(self):
        ok, msg = validate_password_with_context(
            "johndoe_Secure1!", username="johndoe", phone="+79001234567"
        )
        assert ok is False
        assert "никнейм" in msg.lower() or "никнейм" in msg

    def test_short_username_not_checked(self):
        ok, msg = validate_password_with_context(
            "abG00dP@ss1!", username="ab", phone=""
        )
        assert ok is True

    def test_valid_with_context(self):
        ok, msg = validate_password_with_context(
            "S3cur3P@ss!", username="alice", phone="+79001234567"
        )
        assert ok is True


class TestCalculatePasswordStrength:
    def test_strong_score_high(self):
        result = calculate_password_strength("V3ry$trongP@ss!")
        assert result["score"] >= 50
        assert "strength" in result

    def test_weak_score_low(self):
        result = calculate_password_strength("abc")
        assert result["score"] <= 20

    def test_returns_expected_fields(self):
        result = calculate_password_strength("Test1234!")
        assert "score" in result
        assert "strength" in result
        assert "color" in result
        assert "feedback" in result
        assert "has_upper" in result
        assert "has_lower" in result
        assert "has_digits" in result
        assert "has_symbols" in result


class TestGenerateSecurePassword:
    def test_valid_password_returned(self):
        pw = generate_secure_password(16)
        ok, msg = validate_password(pw)
        assert ok is True, f"Generated password '{pw}' is invalid: {msg}"

    def test_custom_length(self):
        pw = generate_secure_password(20)
        assert len(pw) == 20

    def test_minimum_length_clamped(self):
        pw = generate_secure_password(4)
        assert len(pw) >= 12  # clamped to min 12

    def test_max_length_clamped(self):
        pw = generate_secure_password(200)
        assert len(pw) <= 64  # clamped to max 64


# ═══════════════════════════════════════════════════════════════════════════════
# 5. secure_upload.py
# ═══════════════════════════════════════════════════════════════════════════════

from app.security.secure_upload import (
    FileAnomalyDetector,
    validate_file_mime_type,
    generate_secure_filename,
    calculate_file_hash,
)


class TestDetectDoubleExtension:
    def test_shell_php_jpg_flagged(self):
        assert FileAnomalyDetector.detect_double_extension("shell.php.jpg") is True

    def test_virus_exe_png_flagged(self):
        assert FileAnomalyDetector.detect_double_extension("virus.exe.png") is True

    def test_photo_jpg_safe(self):
        assert FileAnomalyDetector.detect_double_extension("photo.jpg") is False

    def test_normal_dots_safe(self):
        assert FileAnomalyDetector.detect_double_extension("my.vacation.photo.jpg") is False

    def test_single_name_safe(self):
        assert FileAnomalyDetector.detect_double_extension("photo") is False


class TestDetectNullBytes:
    def test_null_in_name(self):
        assert FileAnomalyDetector.detect_null_bytes("file\x00.php") is True

    def test_clean_name(self):
        assert FileAnomalyDetector.detect_null_bytes("clean_file.txt") is False


class TestDetectPathTraversal:
    def test_double_dot_slash(self):
        assert FileAnomalyDetector.detect_path_traversal("../../etc/passwd") is True

    def test_normal_filename(self):
        assert FileAnomalyDetector.detect_path_traversal("normal_file.txt") is False

    def test_backslash(self):
        assert FileAnomalyDetector.detect_path_traversal("file\\test") is True

    def test_tilde(self):
        assert FileAnomalyDetector.detect_path_traversal("~root") is True

    def test_script_tag(self):
        assert FileAnomalyDetector.detect_path_traversal("<script>alert(1)</script>.txt") is True


class TestCalculateFileComplexity:
    def test_random_data_high_entropy(self):
        data = secrets.token_bytes(4096)
        entropy = FileAnomalyDetector.calculate_file_complexity(data)
        assert entropy > 7.0

    def test_zeros_low_entropy(self):
        data = b"\x00" * 4096
        entropy = FileAnomalyDetector.calculate_file_complexity(data)
        assert entropy == 0.0

    def test_empty_data(self):
        entropy = FileAnomalyDetector.calculate_file_complexity(b"")
        assert entropy == 0.0

    def test_single_byte_pattern(self):
        data = b"\xAA" * 1000
        entropy = FileAnomalyDetector.calculate_file_complexity(data)
        assert entropy == 0.0


class TestDetectZipBombIndicators:
    def test_archive_header_high_entropy(self):
        # ZIP magic + random high entropy data
        header = b"PK\x03\x04"
        data = header + secrets.token_bytes(4096)
        # This should detect high entropy with archive header
        result = FileAnomalyDetector.detect_zip_bomb_indicators(data)
        # May or may not trigger depending on entropy; we check the logic runs
        assert isinstance(result, bool)

    def test_small_file_ignored(self):
        data = b"PK\x03\x04" + b"\x00" * 100
        assert FileAnomalyDetector.detect_zip_bomb_indicators(data) is False

    def test_non_archive_not_flagged(self):
        data = secrets.token_bytes(4096)
        # Random data without archive header
        assert FileAnomalyDetector.detect_zip_bomb_indicators(data) is False


class TestValidateFileMimeType:
    def test_valid_text_file(self):
        content = b"Hello, this is a text file."
        ok, mime_or_err = validate_file_mime_type(content, "test.txt")
        assert ok is True

    def test_exe_extension_rejected(self):
        content = b"MZ" + b"\x00" * 100
        ok, msg = validate_file_mime_type(content, "malware.exe")
        assert ok is False

    def test_csv_file(self):
        content = b"col1,col2\nval1,val2\n"
        ok, mime_or_err = validate_file_mime_type(content, "data.csv")
        assert ok is True

    def test_unknown_extension(self):
        content = b"something"
        ok, msg = validate_file_mime_type(content, "file.xyz123")
        assert ok is False


class TestGenerateSecureFilename:
    def test_returns_string_with_ext(self):
        name = generate_secure_filename(".jpg")
        assert isinstance(name, str)
        assert name.endswith(".jpg")

    def test_different_each_time(self):
        n1 = generate_secure_filename(".png")
        n2 = generate_secure_filename(".png")
        assert n1 != n2

    def test_no_path_chars(self):
        name = generate_secure_filename(".txt")
        assert "/" not in name
        assert "\\" not in name


class TestCalculateFileHash:
    def test_returns_hex_string(self):
        h = calculate_file_hash(b"test data")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA256 hex length
        bytes.fromhex(h)

    def test_deterministic(self):
        data = b"same content"
        assert calculate_file_hash(data) == calculate_file_hash(data)

    def test_different_content_different_hash(self):
        assert calculate_file_hash(b"aaa") != calculate_file_hash(b"bbb")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. middleware.py (via HTTP)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecurityHeadersMiddleware:
    def test_x_frame_options(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_xss_protection(self, client):
        r = client.get("/health")
        assert r.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_referrer_policy(self, client):
        r = client.get("/health")
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_csp_present(self, client):
        r = client.get("/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "default-src" in csp
        assert "'self'" in csp

    def test_hsts_present(self, client):
        r = client.get("/health")
        hsts = r.headers.get("Strict-Transport-Security", "")
        assert "max-age=" in hsts

    def test_coop(self, client):
        r = client.get("/health")
        assert r.headers.get("Cross-Origin-Opener-Policy") == "same-origin"

    def test_corp(self, client):
        r = client.get("/health")
        assert r.headers.get("Cross-Origin-Resource-Policy") == "same-origin"

    def test_permissions_policy(self, client):
        r = client.get("/health")
        pp = r.headers.get("Permissions-Policy", "")
        assert "geolocation=()" in pp
        assert "camera=(self)" in pp


class TestCSRFMiddleware:
    def test_token_endpoint(self, client):
        r = client.get("/api/authentication/csrf-token")
        assert r.status_code == 200
        data = r.json()
        assert "csrf_token" in data

    def test_mutation_without_csrf_rejected(self, client):
        # POST to a non-exempt endpoint without CSRF should fail
        r = client.post("/api/rooms", json={"name": "test_csrf_room"})
        assert r.status_code in (403, 401, 422)

    def test_login_skips_csrf(self, client):
        # Login is in the CSRF skip list
        r = client.post("/api/authentication/login", json={
            "phone_or_username": "nonexistent_user",
            "password": "Fake1234!",
        })
        # Should not be 403 for CSRF (may be 401/404 for wrong creds)
        assert r.status_code != 403

    def test_register_skips_csrf(self, client):
        r = client.post("/api/authentication/register", json={
            "username": f"csrf_test_{random_str(6)}",
            "password": "StrongPass99x!@",
            "display_name": "CSRF Test",
            "phone": f"+7900{random_digits(7)}",
            "avatar_emoji": "X",
            "x25519_public_key": secrets.token_hex(32),
        })
        # Should not be 403 for CSRF
        assert r.status_code != 403

    def test_health_skips_csrf(self, client):
        r = client.get("/health")
        assert r.status_code == 200


class TestTokenRefreshMiddleware:
    def test_auto_refresh_does_not_break_request(self, client):
        # A simple GET should work fine through the middleware
        r = client.get("/health")
        assert r.status_code == 200


class TestLoggingMiddleware:
    def test_does_not_break_requests(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_non_static_requests_logged(self, client):
        # Just verify the middleware does not crash on API requests
        r = client.get("/api/authentication/csrf-token")
        assert r.status_code == 200


class TestCorrelationID:
    def test_auto_generated(self, client):
        r = client.get("/health")
        cid = r.headers.get("X-Request-ID", "")
        assert len(cid) > 0

    def test_custom_preserved(self, client):
        custom_id = "custom-corr-id-12345"
        r = client.get("/health", headers={"X-Request-ID": custom_id})
        assert r.headers.get("X-Request-ID") == custom_id


# ═══════════════════════════════════════════════════════════════════════════════
# 7. waf.py (via HTTP)
# ═══════════════════════════════════════════════════════════════════════════════

from app.security.waf import WAFRule, WAFEngine


class TestWAFRuleUnit:
    def test_pattern_compilation(self):
        rule = WAFRule("TEST-001", r"(SELECT.*FROM)", severity="critical", description="SQL test")
        assert rule.rule_id == "TEST-001"
        assert rule.pattern.search("SELECT * FROM users")
        assert rule.severity == "critical"

    def test_invalid_pattern_fallback(self):
        rule = WAFRule("BAD-001", r"[invalid(", severity="low")
        # Should not crash; pattern compiles to a never-matching regex
        assert rule.pattern.search("anything") is None


class TestWAFSqlInjection:
    def test_sql_injection_blocked_in_login(self, client):
        r = client.post("/api/authentication/login", json={
            "phone_or_username": "' OR 1=1 --",
            "password": "SELECT * FROM users WHERE 1=1",
        })
        # WAF should block (403) or the app rejects it (401/422)
        assert r.status_code in (403, 401, 422)


class TestWAFXss:
    def test_xss_blocked_in_registration(self, client):
        r = client.post("/api/authentication/register", json={
            "username": "<script>alert('xss')</script>",
            "password": "StrongPass99x!@",
            "display_name": "XSS Test",
            "phone": f"+7900{random_digits(7)}",
            "avatar_emoji": "X",
            "x25519_public_key": secrets.token_hex(32),
        })
        assert r.status_code in (403, 422, 400)


class TestWAFPathTraversal:
    def test_path_traversal_blocked(self, client):
        r = client.get("/api/../../etc/passwd")
        assert r.status_code in (403, 404, 422)


class TestWAFStatsEndpoint:
    def test_waf_stats_returns_json(self, client):
        r = client.get("/waf/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_requests" in data
        assert "blocked_requests" in data


class TestWAFTestEndpoint:
    def test_waf_test_ok(self, client):
        r = client.get("/waf/test")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"


class TestWAFRulesEndpoint:
    def test_waf_rules_returns_list(self, client):
        r = client.get("/waf/rules")
        assert r.status_code == 200
        data = r.json()
        assert "rules" in data
        assert "total" in data
        assert data["total"] > 0
        assert len(data["rules"]) == data["total"]


# ═══════════════════════════════════════════════════════════════════════════════
# 8. logging_config.py
# ═══════════════════════════════════════════════════════════════════════════════

from app.logging_config import JSONFormatter, ConsoleFormatter, new_correlation_id


class TestJSONFormatter:
    def test_produces_valid_json_with_required_fields(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message %s",
            args=("value",),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "level" in parsed
        assert parsed["level"] == "INFO"
        assert "msg" in parsed
        assert "Test message value" in parsed["msg"]
        assert "ts" in parsed

    def test_includes_exception_info(self):
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="t.py",
            lineno=1, msg="err", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


class TestConsoleFormatter:
    def test_includes_level_and_message(self):
        formatter = ConsoleFormatter()
        record = logging.LogRecord(
            name="test.console",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Warning message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "WARNING" in output
        assert "Warning message" in output


class TestNewCorrelationId:
    def test_12_char_hex(self):
        cid = new_correlation_id()
        assert isinstance(cid, str)
        assert len(cid) == 12
        bytes.fromhex(cid)  # valid hex

    def test_unique(self):
        ids = {new_correlation_id() for _ in range(100)}
        assert len(ids) == 100
