"""
Tests for configuration and database setup.
"""
import os
import pytest


class TestConfig:

    def test_config_loaded(self):
        from app.config import Config

        assert Config.HOST is not None
        assert Config.PORT is not None
        assert isinstance(Config.PORT, int)
        assert Config.JWT_SECRET is not None
        assert len(Config.JWT_SECRET) >= 32

    def test_config_db_path(self):
        from app.config import Config

        assert Config.DB_PATH is not None

    def test_config_security_settings(self):
        from app.config import Config

        assert Config.WAF_RATE_LIMIT_REQUESTS > 0
        assert Config.WAF_RATE_LIMIT_WINDOW > 0
        assert Config.WAF_BLOCK_DURATION > 0
        assert Config.MAX_FILE_MB > 0
        assert Config.MAX_FILE_BYTES == Config.MAX_FILE_MB * 1024 * 1024

    def test_config_network_mode(self):
        from app.config import Config

        assert Config.NETWORK_MODE in ("local", "global")

    def test_config_registration_mode(self):
        from app.config import Config

        assert Config.REGISTRATION_MODE in ("open", "invite", "closed")


class TestDatabase:

    def test_init_db_idempotent(self):
        """init_db should be safe to call multiple times."""
        from app.database import init_db

        init_db()  # Should not raise
        init_db()  # Idempotent

    def test_session_factory(self):
        from app.database import SessionLocal

        db = SessionLocal()
        try:
            from sqlalchemy import text
            result = db.execute(text("SELECT 1"))
            assert result.scalar() == 1
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


class TestLogging:

    def test_logging_config_module_exists(self):
        from app.logging_config import setup_logging, new_correlation_id

        cid = new_correlation_id()
        assert len(cid) == 12
        assert isinstance(cid, str)

    def test_json_formatter(self):
        import json
        import logging
        from app.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["msg"] == "test message"
        assert "ts" in parsed
