"""
Structured logging configuration for Vortex Chat.

Supports two modes:
  - console: Human-readable colored output (development)
  - json:    Machine-parseable JSON lines (production)

Usage:
    from app.logging_config import setup_logging
    setup_logging()  # Call once at startup

Features:
    - Correlation ID per request (X-Request-ID header or auto-generated UUID)
    - Log rotation (10MB files, 5 backups)
    - Separate error log file
    - Structured context (user_id, room_id, peer_ip, etc.)
    - Performance timing in log records
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path

# ── Context variables for request-scoped data ────────────────────────────────
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")
request_user_id: ContextVar[int | None] = ContextVar("request_user_id", default=None)


def new_correlation_id() -> str:
    """Generate a short correlation ID for request tracing."""
    return uuid.uuid4().hex[:12]


# ── JSON Formatter ───────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        log_entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "correlation_id": correlation_id.get("-"),
        }

        # Add user context if available
        uid = request_user_id.get(None)
        if uid is not None:
            log_entry["user_id"] = uid

        # Add exception info if present
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields from record
        for key in ("duration_ms", "status_code", "method", "path", "client_ip",
                     "room_id", "peer_ip", "bytes_sent"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        return json.dumps(log_entry, ensure_ascii=False, default=str)


# ── Console Formatter ────────────────────────────────────────────────────────

class ConsoleFormatter(logging.Formatter):
    """Human-readable colored formatter for development."""

    COLORS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[1;31m", # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        cid = correlation_id.get("-")
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]

        msg = f"{color}{timestamp} {record.levelname:7s}{self.RESET} " \
              f"[{cid}] {record.name} — {record.getMessage()}"

        if record.exc_info and record.exc_info[1]:
            msg += "\n" + self.formatException(record.exc_info)

        return msg


# ── Setup Function ───────────────────────────────────────────────────────────

def setup_logging(
    log_format: str | None = None,
    log_level: str | None = None,
    log_dir: str = "logs",
) -> None:
    """
    Configure application-wide logging.

    Args:
        log_format: "json" or "console" (default: from LOG_FORMAT env or "console")
        log_level: Logging level (default: from LOG_LEVEL env or "INFO")
        log_dir: Directory for log files (default: "logs")
    """
    fmt = log_format or os.getenv("LOG_FORMAT", "console")
    level_name = log_level or os.getenv("LOG_LEVEL", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)

    # Create log directory
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers
    root.handlers.clear()

    # ── Console handler ──────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if fmt == "json":
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ConsoleFormatter())

    root.addHandler(console_handler)

    # ── File handler (rotating, all levels) ──────────────────────────────
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / "vortex.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(JSONFormatter())
    root.addHandler(file_handler)

    # ── Error file handler (errors only) ─────────────────────────────────
    error_handler = logging.handlers.RotatingFileHandler(
        log_path / "vortex-error.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JSONFormatter())
    root.addHandler(error_handler)

    # ── Silence noisy loggers ────────────────────────────────────────────
    for name in ("uvicorn.access", "httpx", "httpcore", "websockets"):
        logging.getLogger(name).setLevel(logging.WARNING)

    logging.getLogger("uvicorn.error").setLevel(level)

    root_logger = logging.getLogger(__name__)
    root_logger.info(
        "Logging configured: format=%s level=%s dir=%s",
        fmt, level_name, log_dir,
    )
