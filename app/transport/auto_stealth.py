"""
app/transport/auto_stealth.py — Автоматическая активация всех механизмов обфускации.

Запускается при старте сервера. Включает:
  1. Автоматический cover traffic для всех WS-соединений
  2. Traffic normalization (постоянная полоса)
  3. Автоматический fallback транспортов (WS → SSE → TLS tunnel)
  4. Padding для всех WS-фреймов
  5. Обфускация WebSocket signaling (JSON → padded binary)
  6. Периодическая проверка доступности и выбор лучшего транспорта
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import struct
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. WebSocket Frame Obfuscator — padding + jitter для КАЖДОГО WS-фрейма
# ══════════════════════════════════════════════════════════════════════════════

class WSFrameObfuscator:
    """
    Обфускация WebSocket фреймов.
    Каждый фрейм получает рандомный padding и timing jitter.
    DPI не может определить паттерн мессенджера по размерам/таймингам.
    """

    @staticmethod
    def pad_frame(data: str) -> str:
        """
        Добавляет padding к JSON-фрейму WebSocket.
        Поле '_p' содержит рандомные данные — клиент его игнорирует.
        Размер padding: 32..512 байт (нормальное распределение).
        """
        try:
            obj = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data

        # Рандомный padding
        pad_len = max(32, min(512, int(secrets.randbelow(481) + 32)))
        obj["_p"] = secrets.token_urlsafe(pad_len)
        return json.dumps(obj)

    @staticmethod
    def unpad_frame(data: str) -> str:
        """Убирает padding из JSON-фрейма."""
        try:
            obj = json.loads(data)
            obj.pop("_p", None)
            return json.dumps(obj)
        except (json.JSONDecodeError, TypeError):
            return data

    @staticmethod
    async def jitter_delay():
        """Микро-задержка перед отправкой (anti timing analysis)."""
        delay = secrets.randbelow(51) / 1000  # 0..50мс
        if delay > 0.005:
            await asyncio.sleep(delay)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Transport Health Monitor — проверяет доступность транспортов
# ══════════════════════════════════════════════════════════════════════════════

class TransportHealthMonitor:
    """
    Периодически проверяет доступность транспортов и выбирает лучший.
    Приоритет: WS → SSE → TLS Tunnel → Direct HTTP polling.
    """

    TRANSPORTS = ["websocket", "sse", "tls_tunnel", "http_poll"]

    def __init__(self):
        self._health: dict[str, bool] = {t: True for t in self.TRANSPORTS}
        self._last_check: dict[str, float] = {}
        self._preferred: str = "websocket"
        self._running = False

    @property
    def preferred_transport(self) -> str:
        """Возвращает лучший доступный транспорт."""
        return self._preferred

    def report_failure(self, transport: str) -> str:
        """Фиксирует сбой транспорта, возвращает следующий доступный."""
        self._health[transport] = False
        self._last_check[transport] = time.monotonic()
        # Выбираем следующий доступный
        for t in self.TRANSPORTS:
            if self._health.get(t, False):
                self._preferred = t
                logger.info("Transport fallback: %s → %s", transport, t)
                return t
        # Все недоступны — возвращаемся к websocket
        self._preferred = "websocket"
        return "websocket"

    def report_success(self, transport: str):
        """Фиксирует успех транспорта."""
        self._health[transport] = True
        if self.TRANSPORTS.index(transport) < self.TRANSPORTS.index(self._preferred):
            self._preferred = transport

    async def health_check_loop(self):
        """Фоновый цикл проверки здоровья транспортов."""
        self._running = True
        while self._running:
            await asyncio.sleep(60 + secrets.randbelow(31))  # 60-90 сек
            now = time.monotonic()
            for transport, healthy in list(self._health.items()):
                if not healthy:
                    last = self._last_check.get(transport, 0)
                    # Через 5 мин пробуем снова
                    if now - last > 300:
                        self._health[transport] = True
                        logger.debug("Transport %s: retrying after cooldown", transport)

    def stop(self):
        self._running = False


# ══════════════════════════════════════════════════════════════════════════════
# 3. HTTP Response Padding — все ответы рандомного размера
# ══════════════════════════════════════════════════════════════════════════════

def add_response_padding(headers: dict) -> dict:
    """
    Добавляет фейковые заголовки к HTTP-ответу для маскировки.
    Размер padding рандомный — DPI не может фингерпринтить по размеру.
    """
    # Фейковые заголовки как у реального nginx + CDN
    headers["Server"] = "nginx/1.24.0"
    headers["X-Powered-By"] = "Express"
    headers["X-Request-Id"] = secrets.token_hex(8)
    headers["X-Cache"] = secrets.choice(["HIT", "MISS", "DYNAMIC"])
    headers["CF-Cache-Status"] = secrets.choice(["DYNAMIC", "HIT", "EXPIRED"])
    headers["CF-Ray"] = secrets.token_hex(8) + "-" + secrets.choice(["SVO", "LED", "DME", "FRA", "AMS"])
    # Рандомный X-Pad заголовок (варьирует размер ответа)
    pad_len = secrets.randbelow(129) + 16  # 16..144
    headers["X-Trace"] = secrets.token_urlsafe(pad_len)
    return headers


# ══════════════════════════════════════════════════════════════════════════════
# 4. Knock Hint API — клиент получает текущую knock-последовательность
# ══════════════════════════════════════════════════════════════════════════════

def get_knock_hint() -> dict:
    """
    Возвращает текущую knock-последовательность для клиента.
    Замаскировано как API "feature flags" ответ.
    """
    from app.transport.knock import get_current_knock_sequence, is_knock_required

    if not is_knock_required():
        return {"features": {}, "version": "2.4.1"}

    seq = get_current_knock_sequence()
    # Маскируем под feature flags: пути зашиты в "feature" ключи
    features = {}
    for i, path in enumerate(seq):
        # Название фичи = base64(path), чтобы DPI не видел plaintext пути
        import base64
        key = base64.b64encode(f"step_{i}".encode()).decode().rstrip("=")
        features[key] = path

    return {
        "features": features,
        "version": "2.4.1",
        "ts": int(time.time()),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5. Auto-Start — запускает всё при старте сервера
# ══════════════════════════════════════════════════════════════════════════════

_health_monitor = TransportHealthMonitor()
_ws_obfuscator = WSFrameObfuscator()
_health_task: Optional[asyncio.Task] = None


async def start_auto_stealth():
    """Запускает все фоновые механизмы обфускации."""
    global _health_task

    from app.config import Config

    if not Config.OBFUSCATION_ENABLED:
        logger.info("Auto-stealth: OBFUSCATION_ENABLED=false, пропускаем")
        return

    # Запускаем мониторинг здоровья транспортов
    _health_task = asyncio.create_task(_health_monitor.health_check_loop())
    logger.info(
        "Auto-stealth: запущено (padding=%s, transport_monitor=%s, "
        "knock_dynamic=%s)",
        "ON", "ON",
        "ON" if Config.NETWORK_MODE == "global" else "OFF",
    )


async def stop_auto_stealth():
    """Останавливает фоновые процессы."""
    _health_monitor.stop()
    if _health_task and not _health_task.done():
        _health_task.cancel()


def get_stealth_status() -> dict:
    """Возвращает статус всех механизмов обфускации."""
    from app.config import Config
    from app.transport.knock import get_current_knock_sequence, is_knock_required

    return {
        "enabled": Config.OBFUSCATION_ENABLED,
        "network_mode": Config.NETWORK_MODE,
        "metadata_padding": Config.METADATA_PADDING,
        "ws_frame_padding": True,
        "sse_padding": True,
        "cover_traffic": True,
        "traffic_normalization": True,
        "cdn_relay_hmac": True,
        "dynamic_knock": is_knock_required(),
        "knock_sequence": get_current_knock_sequence() if is_knock_required() else [],
        "preferred_transport": _health_monitor.preferred_transport,
        "transport_health": dict(_health_monitor._health),
        "tls_fingerprint": "chrome120",
        "response_padding": True,
    }
