"""
app/transport/knock.py — Anti-probing: knock sequence для WebSocket.

Проблема: ТСПУ/DPI активно зондирует серверы — подключается и пробует
WebSocket upgrade. Если сервер принимает — помечается как мессенджер.

Решение: WebSocket доступен только после правильной "knock sequence".
Клиент должен посетить определённые страницы в определённом порядке,
получить одноразовый токен, и передать его при WS-подключении.

Без knock sequence:
  - HTTP запросы -> cover website (CloudSync Solutions)
  - WebSocket upgrade -> reject (404 или cover HTML)
  - Сервер неотличим от обычного сайта

С knock sequence:
  1. GET /cover/pricing     -> получает cookie "sid=xxx"
  2. GET /cover/about       -> cookie обновляется "sid=yyy"
  3. WS /ws/... ?knock=token -> WebSocket подключается

Knock токен:
  - Одноразовый (удаляется после использования)
  - TTL 60 секунд
  - Привязан к IP
  - Хранится в памяти (не в БД)
"""
from __future__ import annotations

import logging
import secrets
import time
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_KNOCK_TTL = 3600  # 1 час — нужен для нескольких WS за сессию
_knock_tokens: dict[str, float] = {}  # token -> expires_at (monotonic)
_knock_progress: dict[str, tuple[list[str], float]] = {}  # ip -> ([visited pages], created_at)
_PROGRESS_TTL = 120  # секунд — TTL для незавершённых knock-последовательностей
_lock = threading.Lock()

# Последовательность страниц (клиент должен посетить в этом порядке)
KNOCK_SEQUENCE = ["/cover/pricing", "/cover/about"]


def record_page_visit(session_id: str, path: str) -> Optional[str]:
    """
    Записывает посещение cover-страницы.
    session_id — уникальный идентификатор сессии (cookie или IP).
    Если последовательность завершена — возвращает knock_token.
    """
    with _lock:
        _cleanup_expired()

        if session_id not in _knock_progress:
            _knock_progress[session_id] = ([], time.monotonic())

        progress, _ = _knock_progress[session_id]

        # Проверяем что это следующая страница в последовательности
        expected_idx = len(progress)
        if expected_idx < len(KNOCK_SEQUENCE) and path == KNOCK_SEQUENCE[expected_idx]:
            progress.append(path)

        # Если последовательность завершена — генерируем токен
        if len(progress) >= len(KNOCK_SEQUENCE):
            token = secrets.token_urlsafe(32)
            _knock_tokens[token] = time.monotonic() + _KNOCK_TTL
            del _knock_progress[session_id]
            logger.debug(f"Knock sequence completed for {session_id}, token issued")
            return token

        return None


def verify_knock(token: str) -> bool:
    """
    Проверяет knock-токен. Многоразовый в пределах TTL
    (нужен для нескольких WS-соединений: chat + signal + notifications).
    """
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
    # Очистка незавершённых knock-последовательностей (защита от memory leak)
    expired_progress = [ip for ip, (_, ts) in _knock_progress.items() if now - ts > _PROGRESS_TTL]
    for ip in expired_progress:
        del _knock_progress[ip]
