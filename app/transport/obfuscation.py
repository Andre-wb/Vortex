"""
app/transport/obfuscation.py — Anti-DPI обфускация трафика.

Три уровня защиты от Deep Packet Inspection:
  1. Рандомизация размеров — непрерывное распределение, не фиксированные бины
  2. Рандомизация таймингов — нет характерных интервалов
  3. Cover traffic — фейковый трафик для маскировки пауз

Цель: трафик Vortex должен быть неотличим от обычного HTTPS-серфинга
для систем типа ТСПУ (Роскомнадзор), GFW (Китай), NeTFilt и т.д.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import struct
import time
from typing import Optional

logger = logging.getLogger(__name__)


class TrafficObfuscator:
    """
    Обфускатор трафика. Делает паттерны Vortex неотличимыми от обычного HTTPS.
    """

    # Заголовки маскировки под nginx
    COVER_HEADERS = {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "Express",
        "Vary": "Accept-Encoding",
    }

    @staticmethod
    def pad_message(data: bytes, target_sizes: list[int] | None = None) -> bytes:
        """
        Рандомный padding с непрерывным распределением размеров.

        Формат: [2B real_len][2B pad_len][real_data][random_padding]

        Если target_sizes задан — размер подгоняется под один из целевых
        (имитация типичных веб-ресурсов: 1K CSS, 5K JSON, 15K HTML, 30K JS).
        """
        real_len = len(data)

        if real_len > 65535:
            return data

        if target_sizes:
            # Выбираем ближайший целевой размер >= real_len + 4
            candidates = [s for s in target_sizes if s >= real_len + 4]
            if candidates:
                target = min(candidates)
                pad_size = max(16, target - real_len - 4)
            else:
                pad_size = max(16, min(512, int(random.gauss(128, 64))))
        else:
            # Случайный padding (16-512 байт, нормальное распределение)
            pad_size = max(16, min(512, int(random.gauss(128, 64))))

        header = struct.pack(">HH", real_len, pad_size)
        padding = os.urandom(pad_size)

        return header + data + padding

    # Типичные размеры веб-ресурсов для маскировки
    WEB_SIZES = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

    @staticmethod
    def unpad_message(padded: bytes) -> bytes:
        """Извлечение оригинального сообщения."""
        if len(padded) < 4:
            return padded
        real_len, pad_len = struct.unpack(">HH", padded[:4])
        if 4 + real_len > len(padded):
            return padded  # не запаковано
        return padded[4:4 + real_len]

    @staticmethod
    def random_delay() -> float:
        """
        Случайная задержка с экспоненциальным распределением.
        Среднее: 50мс, макс: ~300мс.
        Имитирует latency реальных веб-запросов.
        """
        return min(0.3, random.expovariate(20))

    @staticmethod
    async def add_timing_jitter() -> None:
        """Добавляет случайную задержку перед отправкой."""
        delay = TrafficObfuscator.random_delay()
        if delay > 0.005:  # не ждём менее 5мс
            await asyncio.sleep(delay)

    @staticmethod
    def get_cover_headers() -> dict:
        return dict(TrafficObfuscator.COVER_HEADERS)

    @staticmethod
    def randomize_interval(base_seconds: float, jitter_ratio: float = 0.5) -> float:
        """
        Рандомизация интервала. Вместо фиксированных 25с/30с:
        randomize_interval(25, 0.5) -> случайное от 12.5 до 37.5
        randomize_interval(30, 0.7) -> случайное от 9 до 51
        """
        min_val = base_seconds * (1 - jitter_ratio)
        max_val = base_seconds * (1 + jitter_ratio)
        return random.uniform(min_val, max_val)


class TrafficNormalizer:
    """
    Нормализация трафика — постоянная полоса пропускания.

    Вместо: burst -> silence -> burst (паттерн мессенджера)
    Делаем: постоянный поток X Кбит/сек (паттерн видео-стриминга)

    Когда нет реальных данных — отправляем padding.
    Когда есть — отправляем данные + меньше padding.
    Итого: полоса всегда ~target_kbps.
    """

    def __init__(self, target_kbps: float = 64.0):
        self.target_kbps = target_kbps
        self.target_bytes_per_sec = target_kbps * 1024 / 8
        self._bytes_sent_this_sec = 0
        self._last_reset = time.monotonic()
        self._running = False

    def record_sent(self, nbytes: int) -> None:
        """Записывает отправку реальных данных."""
        now = time.monotonic()
        if now - self._last_reset >= 1.0:
            self._bytes_sent_this_sec = 0
            self._last_reset = now
        self._bytes_sent_this_sec += nbytes

    def get_padding_needed(self) -> int:
        """Сколько padding-байт нужно отправить чтобы заполнить полосу."""
        now = time.monotonic()
        elapsed = now - self._last_reset
        if elapsed >= 1.0:
            self._bytes_sent_this_sec = 0
            self._last_reset = now
            elapsed = 0.0

        target_for_elapsed = self.target_bytes_per_sec * max(elapsed, 0.1)
        deficit = int(target_for_elapsed - self._bytes_sent_this_sec)
        return max(0, deficit)

    async def normalize_loop(self, send_fn) -> None:
        """
        Фоновый цикл: каждые 100мс проверяет нужен ли padding.
        send_fn: async callable(bytes) для отправки данных.
        """
        self._running = True
        while self._running:
            await asyncio.sleep(0.1)  # 100мс интервал
            try:
                needed = self.get_padding_needed()
                if needed > 64:  # минимум 64 байта чтобы не спамить
                    padding = b"\x00" + os.urandom(min(needed, 4096))
                    await send_fn(padding)
                    self.record_sent(len(padding))
            except Exception:
                pass

    def stop(self):
        self._running = False
