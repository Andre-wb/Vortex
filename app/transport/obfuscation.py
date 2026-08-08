"""app/transport/obfuscation.py — Anti-DPI обфускация трафика.

Три уровня защиты от Deep Packet Inspection:
  1. Рандомизация размеров — непрерывное распределение, не фиксированные бины
  2. Рандомизация таймингов — нет характерных интервалов
  3. Cover traffic — фейковый трафик для маскировки пауз

Цель: трафик Vortex должен быть неотличим от обычного HTTPS-серфинга
для систем типа ТСПУ (Роскомнадзор), GFW (Китай), NeTFilt и т.д.

Формат конверта, распределения размеров и задержек, список cover-заголовков
и расчёт нормализатора полосы считает Rust (`vortex-transport`, крейт
`obfuscation`). Здесь остались только адаптеры к asyncio: сам сон и фоновый
цикл нормализатора.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time

from app.transport.obfuscation_backend import Obfuscation, RustTrafficNormalizer

logger = logging.getLogger(__name__)

_ENGINE = Obfuscation()


class TrafficObfuscator:
    """Обфускатор трафика. Делает паттерны Vortex неотличимыми от обычного HTTPS."""

    COVER_HEADERS = _ENGINE.cover_headers()
    WEB_SIZES = _ENGINE.web_sizes

    @staticmethod
    def pad_message(data: bytes, target_sizes: list[int] | None = None) -> bytes:
        """Конверт с паддингом: [2B real_len][2B pad_len][real_data][padding].

        Сообщение длиннее 65535 байт в формат не помещается — отказ, а не
        возврат исходных байт: такой «конверт» разобрать обратно нельзя.
        """
        return _ENGINE.pad(data, target_sizes)

    @staticmethod
    def unpad_message(padded: bytes) -> bytes:
        """Извлечение оригинального сообщения. Буфер, не являющийся конвертом, отвергается."""
        return _ENGINE.unpad(padded)

    @staticmethod
    def random_delay() -> float:
        """Случайная задержка, имитирующая latency реальных веб-запросов."""
        return _ENGINE.delay()

    @staticmethod
    async def add_timing_jitter() -> None:
        delay = _ENGINE.delay()
        if _ENGINE.is_worth_waiting(delay):
            await asyncio.sleep(delay)

    @staticmethod
    def get_cover_headers() -> dict:
        return _ENGINE.cover_headers()

    @staticmethod
    def randomize_interval(base_seconds: float, jitter_ratio: float = 0.5) -> float:
        """Рандомизация интервала: randomize_interval(25, 0.5) -> от 12.5 до 37.5."""
        return _ENGINE.interval(base_seconds, jitter_ratio)


class TrafficNormalizer:
    """Нормализация трафика — постоянная полоса пропускания.

    Вместо: burst -> silence -> burst (паттерн мессенджера)
    Делаем: постоянный поток X Кбит/сек (паттерн видео-стриминга)

    Учёт долга ведёт Rust; здесь только часы и фоновый цикл отправки.
    """

    def __init__(self, target_kbps: float = 64.0):
        self._inner = RustTrafficNormalizer(target_kbps)
        self._running = False

    @property
    def target_kbps(self) -> float:
        return self._inner.target_kbps

    @property
    def target_bytes_per_sec(self) -> float:
        return self._inner.target_bytes_per_sec

    def record_sent(self, nbytes: int) -> None:
        self._inner.record_sent(time.monotonic(), nbytes)

    def get_padding_needed(self) -> int:
        return self._inner.padding_needed(time.monotonic())

    async def normalize_loop(self, send_fn) -> None:
        """Фоновый цикл: каждые 100мс проверяет нужен ли padding."""
        self._running = True
        while self._running:
            await asyncio.sleep(0.1)
            with contextlib.suppress(Exception):
                needed = self.get_padding_needed()
                if needed:
                    padding = os.urandom(needed)
                    await send_fn(padding)
                    self.record_sent(len(padding))

    def stop(self):
        self._running = False
