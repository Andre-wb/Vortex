"""Загрузка Rust-разборщика обёртки комнатного ключа.

Формы конверта (классический ECIES и post-quantum гибрид), длины полей, строгий
hex и правило «что считается гибридом» живут в крейте `vortex-proto` и выставлены
в Python через `vortex_chat`. Здесь только загрузка расширения — Python-fallback-а
нет намеренно: вторая копия правил формата означала бы дрейф между рантаймами.
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
        WRAPPED_KEY_LIMITS,
        wrapped_key_parse,
        wrapped_key_stored,
    )
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = [
    "WRAPPED_KEY_LIMITS",
    "wrapped_key_parse",
    "wrapped_key_stored",
]
