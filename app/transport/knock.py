"""
app/transport/knock.py — Anti-probing: динамический knock sequence для WebSocket.

Проблема: ТСПУ/DPI активно зондирует серверы — подключается и пробует
WebSocket upgrade. Если сервер принимает — помечается как мессенджер.

Решение: WebSocket доступен только после правильной "knock sequence".
Клиент должен посетить определённые страницы в определённом порядке,
получить одноразовый токен, и передать его при WS-подключении.

v2: Динамическая генерация knock-путей — DPI не может выучить паттерн.
    Пути ротируются каждые ROTATION_INTERVAL секунд.
    TTL рандомизирован (30 мин — 2 ч).
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ── Dynamic knock path generation ────────────────────────────────────────────
# Вместо фиксированных /cover/pricing, /cover/about
# генерируем пути на основе HMAC(server_secret, time_bucket)
# Все клиенты получают текущие пути через /api/transport/knock-hint

_ROTATION_INTERVAL = 600  # Ротация путей каждые 10 минут
_COVER_PATH_POOL = [
    "/cover/pricing", "/cover/about", "/cover/docs", "/cover/contact",
    "/cover/blog", "/cover/careers", "/cover/status", "/cover/legal",
    "/cover/faq", "/cover/support", "/cover/partners", "/cover/api",
    "/cover/security", "/cover/compliance", "/cover/changelog",
    "/cover/integrations", "/cover/enterprise", "/cover/demo",
]
_KNOCK_SEQUENCE_LEN = 2  # Сколько страниц нужно посетить

_server_secret: bytes = b""


def _ensure_secret() -> bytes:
    global _server_secret
    if not _server_secret:
        from app.config import Config
        _server_secret = hashlib.sha256(Config.JWT_SECRET.encode()).digest()
    return _server_secret


def _get_time_bucket() -> int:
    """Текущий time bucket для ротации путей."""
    return int(time.time()) // _ROTATION_INTERVAL


def get_current_knock_sequence() -> list[str]:
    """
    Возвращает текущую knock-последовательность (динамическую).
    Меняется каждые ROTATION_INTERVAL секунд.
    Предыдущая последовательность тоже принимается (grace period).
    """
    secret = _ensure_secret()
    bucket = _get_time_bucket()
    # Детерминированный выбор путей из пула на основе HMAC + time bucket
    h = hashlib.sha256(secret + bucket.to_bytes(8, "big")).digest()
    indices = []
    for i in range(_KNOCK_SEQUENCE_LEN):
        idx = h[i * 4] % len(_COVER_PATH_POOL)
        # Избегаем дубликатов
        while idx in indices:
            idx = (idx + 1) % len(_COVER_PATH_POOL)
        indices.append(idx)
    return [_COVER_PATH_POOL[i] for i in indices]


def _get_previous_knock_sequence() -> list[str]:
    """Предыдущая knock-последовательность (grace period при ротации)."""
    secret = _ensure_secret()
    bucket = _get_time_bucket() - 1
    h = hashlib.sha256(secret + bucket.to_bytes(8, "big")).digest()
    indices = []
    for i in range(_KNOCK_SEQUENCE_LEN):
        idx = h[i * 4] % len(_COVER_PATH_POOL)
        while idx in indices:
            idx = (idx + 1) % len(_COVER_PATH_POOL)
        indices.append(idx)
    return [_COVER_PATH_POOL[i] for i in indices]


# ── Knock state ──────────────────────────────────────────────────────────────

_knock_tokens: dict[str, float] = {}  # token -> expires_at (monotonic)
_knock_progress: dict[str, tuple[list[str], float]] = {}
_PROGRESS_TTL = 120
_lock = threading.Lock()


def _random_ttl() -> float:
    """Рандомизированный TTL для knock-токенов (30 мин — 2 часа)."""
    return 1800 + secrets.randbelow(5401)  # 1800..7200 сек


def record_page_visit(session_id: str, path: str) -> Optional[str]:
    """
    Записывает посещение cover-страницы.
    Проверяет против текущей И предыдущей knock-последовательности.
    """
    with _lock:
        _cleanup_expired()

        if session_id not in _knock_progress:
            _knock_progress[session_id] = ([], time.monotonic())

        progress, _ = _knock_progress[session_id]
        expected_idx = len(progress)

        # Проверяем против текущей и предыдущей последовательности
        current_seq = get_current_knock_sequence()
        prev_seq = _get_previous_knock_sequence()

        matched = False
        if expected_idx < len(current_seq) and path == current_seq[expected_idx]:
            matched = True
        elif expected_idx < len(prev_seq) and path == prev_seq[expected_idx]:
            matched = True

        if matched:
            progress.append(path)

        # Последовательность завершена
        if len(progress) >= _KNOCK_SEQUENCE_LEN:
            token = secrets.token_urlsafe(32)
            ttl = _random_ttl()
            _knock_tokens[token] = time.monotonic() + ttl
            del _knock_progress[session_id]
            logger.debug("Knock sequence completed for %s, token issued (TTL=%ds)", session_id, int(ttl))
            return token

        return None


def verify_knock(token: str) -> bool:
    """Проверяет knock-токен. Многоразовый в пределах TTL."""
    if not token:
        return False
    with _lock:
        expires = _knock_tokens.get(token)
        if expires is None:
            return False
        if time.monotonic() > expires:
            _knock_tokens.pop(token, None)
            return False
        return True


def is_knock_required() -> bool:
    """Проверяет, включён ли knock sequence (только в global mode)."""
    from app.config import Config
    return Config.NETWORK_MODE == "global" and Config.OBFUSCATION_ENABLED


def _cleanup_expired() -> None:
    """Удаляет просроченные токены и незавершённый knock-прогресс."""
    now = time.monotonic()
    expired_tokens = [t for t, exp in _knock_tokens.items() if now > exp]
    for t in expired_tokens:
        del _knock_tokens[t]
    expired_progress = [ip for ip, (_, ts) in _knock_progress.items() if now - ts > _PROGRESS_TTL]
    for ip in expired_progress:
        del _knock_progress[ip]
