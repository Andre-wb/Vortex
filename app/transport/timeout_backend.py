"""Загрузка бюджета чтения из Rust.

Сколько времени клиенту отводится на то, чтобы досказать рукопожатие, —
одно число на все транспорты, и живёт оно в крейте `vortex-transport`
(`timeout::config`). Python здесь только спит и читает: сколько осталось,
считает `ReadDeadline`. Python-fallback-а нет намеренно — вторая копия
числа это ровно тот дефект, ради которого оно и вынесено.
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
    from vortex_chat import HANDSHAKE_TIMEOUT_SECS, ReadDeadline
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = ["HANDSHAKE_TIMEOUT_SECS", "ReadDeadline"]
