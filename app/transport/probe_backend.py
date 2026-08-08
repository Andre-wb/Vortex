"""Загрузка Rust-реализации проб цензуры и мониторинга задержек.

Каталог транспортов (имя, приоритет, предел ожидания, вид пробы), вывод
probe-токена, чтение ответа, выбор лучшего транспорта, расписание повторов,
разбор истории задержек и панель блокировок по регионам живут в крейте
`vortex-transport` и выставлены в Python через `vortex_chat`. Здесь только
загрузка расширения — Python-fallback-а нет намеренно: тихий откат означал бы
вторую копию каталога и вторую копию правил, по которым транспорт признаётся
работающим.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_BUILD_HINT = (
    "Модуль vortex_chat не установлен. Соберите расширение:\n"
    "    make rust-build\n"
    "или вручную:\n"
    "    maturin develop --release -m rust_utils/Cargo.toml"
)

try:
    from vortex_chat import (
        CensorshipDashboard,
        CensorshipProbe,
        LatencyMonitor,
        ServiceWorkerProfile,
    )
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = [
    "CensorshipDashboard",
    "CensorshipProbe",
    "LatencyMonitor",
    "ServiceWorkerProfile",
]
