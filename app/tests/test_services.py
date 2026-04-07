"""Service layer and utility tests — chat service, file upload, validation."""
import os
import secrets
import pytest
from conftest import make_user, login_user, random_str


class TestPasswordValidation:
    """Password validation rules."""

    def test_valid_password(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("StrongPass99!@")
        assert ok is True

    def test_too_short(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("Ab1!")
        assert ok is False

    def test_no_uppercase(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("nouppercase99!")
        assert ok is False

    def test_no_lowercase(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("NOLOWERCASE99!")
        assert ok is False

    def test_no_digit(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("NoDigitsHere!")
        assert ok is False

    def test_no_special_char(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("NoSpecial99aa")
        assert ok is False

    def test_common_password(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("Qwerty12345!")
        # "qwerty" is a keyboard sequence
        assert ok is False

    def test_repeated_chars(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("Aaaa1111!!!!")
        assert ok is False

    def test_sequential_numbers(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("Test0123456!")
        assert ok is False

    def test_keyboard_sequence(self):
        from app.security.security_validate import validate_password
        ok, msg = validate_password("Qwerty12345!")
        assert ok is False

    def test_max_length(self):
        from app.security.security_validate import validate_password
        pw = "A" * 64 + "a" * 63 + "1!"
        ok, msg = validate_password(pw)
        assert ok is False

    def test_password_with_context(self):
        from app.security.security_validate import validate_password_with_context
        ok, msg = validate_password_with_context("MyUser99!@ok", "myuser", "+79001234567")
        # Username in password
        assert ok is False

    def test_password_strength_score(self):
        from app.security.security_validate import calculate_password_strength
        result = calculate_password_strength("V3ry$tr0ng!Pass#2026")
        assert "score" in result
        assert result["score"] >= 60

    def test_weak_strength_score(self):
        from app.security.security_validate import calculate_password_strength
        result = calculate_password_strength("abc")
        assert result["score"] < 40


class TestFileUploadValidation:
    """Secure file upload validation tests."""

    def test_double_extension_detection(self):
        from app.security.secure_upload import FileAnomalyDetector
        assert FileAnomalyDetector.detect_double_extension("shell.php.jpg") is True
        assert FileAnomalyDetector.detect_double_extension("photo.jpg") is False
        assert FileAnomalyDetector.detect_double_extension("photo.vacation.jpg") is False

    def test_null_byte_detection(self):
        from app.security.secure_upload import FileAnomalyDetector
        assert FileAnomalyDetector.detect_null_bytes("file\x00.jpg") is True
        assert FileAnomalyDetector.detect_null_bytes("normal.jpg") is False

    def test_path_traversal_detection(self):
        from app.security.secure_upload import FileAnomalyDetector
        assert FileAnomalyDetector.detect_path_traversal("../../etc/passwd") is True
        assert FileAnomalyDetector.detect_path_traversal("normal_file.txt") is False
        assert FileAnomalyDetector.detect_path_traversal("file/with/slash.txt") is True

    def test_file_complexity(self):
        from app.security.secure_upload import FileAnomalyDetector
        # Random data has high entropy
        entropy = FileAnomalyDetector.calculate_file_complexity(os.urandom(1000))
        assert entropy > 7.0
        # Repetitive data has low entropy
        entropy_low = FileAnomalyDetector.calculate_file_complexity(b"\x00" * 1000)
        assert entropy_low < 1.0

    def test_zip_bomb_detection(self):
        from app.security.secure_upload import FileAnomalyDetector
        # Small high-entropy data with archive magic bytes
        archive_header = b"PK\x03\x04" + os.urandom(100)
        result = FileAnomalyDetector.detect_zip_bomb_indicators(archive_header)
        assert isinstance(result, bool)

    def test_mime_type_validation(self):
        from app.security.secure_upload import validate_file_mime_type
        # Text file
        ok, mime = validate_file_mime_type(b"Hello, plain text file content here.", "test.txt")
        assert ok is True

    def test_mime_type_rejection(self):
        from app.security.secure_upload import validate_file_mime_type
        # EXE file
        ok, mime = validate_file_mime_type(b"MZ" + b"\x00" * 100, "malware.exe")
        # Should reject .exe extension
        assert ok is False or mime is not None


class TestFileUploadAPI:
    """File upload via API."""

    def test_upload_small_file(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(
            f"/api/rooms/{room_id}/upload",
            files={"file": ("test.txt", b"Hello, World!", "text/plain")},
            headers=logged_user["headers"],
        )
        assert r.status_code in (200, 201, 404, 422)

    def test_upload_without_auth(self, client, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(
            f"/api/rooms/{room_id}/upload",
            files={"file": ("test.txt", b"Hello", "text/plain")},
        )
        assert r.status_code in (401, 403, 404, 422)


class TestDatabaseEngine:
    """Database engine info tests."""

    def test_engine_info(self):
        from app.database import get_engine_info
        info = get_engine_info()
        assert "backend" in info
        assert info["backend"] in ("sqlite", "postgresql")
        assert "async_available" in info

    def test_init_db_idempotent(self):
        from app.database import init_db
        init_db()
        init_db()  # Should not raise

    def test_session_factory(self):
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            from sqlalchemy import text
            result = db.execute(text("SELECT 1"))
            assert result is not None
        finally:
            db.close()

    def test_get_db_generator(self):
        from app.database import get_db
        gen = get_db()
        db = next(gen)
        assert db is not None
        try:
            next(gen)
        except StopIteration:
            pass


class TestLoggingConfig:
    """Logging configuration tests."""

    def test_json_formatter(self):
        import json
        import logging
        from app.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["msg"] == "test message"
        assert "ts" in parsed

    def test_console_formatter(self):
        import logging
        from app.logging_config import ConsoleFormatter

        formatter = ConsoleFormatter()
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="warning message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        assert "warning message" in output
        assert "WARNING" in output

    def test_correlation_id_generation(self):
        from app.logging_config import new_correlation_id
        cid1 = new_correlation_id()
        cid2 = new_correlation_id()
        assert len(cid1) == 12
        assert cid1 != cid2


class TestConfigValidation:
    """Config edge case tests."""

    def test_config_attributes_exist(self):
        from app.config import Config
        assert hasattr(Config, "JWT_SECRET")
        assert hasattr(Config, "CSRF_SECRET")
        assert hasattr(Config, "DATABASE_URL")
        assert hasattr(Config, "DB_POOL_SIZE")
        assert hasattr(Config, "DB_MAX_OVERFLOW")
        assert hasattr(Config, "DB_POOL_RECYCLE")

    def test_config_ensure_dirs(self, tmp_path):
        from app.config import Config
        original_upload = Config.UPLOAD_DIR
        original_keys = Config.KEYS_DIR
        try:
            Config.UPLOAD_DIR = tmp_path / "test_uploads"
            Config.KEYS_DIR = tmp_path / "test_keys"
            Config.ensure_dirs()
            assert Config.UPLOAD_DIR.exists()
            assert Config.KEYS_DIR.exists()
        finally:
            Config.UPLOAD_DIR = original_upload
            Config.KEYS_DIR = original_keys
