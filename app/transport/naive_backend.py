"""Загрузка Rust-реализации NaiveProxy.

Сборка Caddyfile, проверка имени, пароля, probe-домена и адреса backend-а,
а также построение URL прокси с percent-encoding живут в крейте
`vortex-transport` и выставлены в Python через `vortex_chat`. Здесь только
загрузка расширения — Python-fallback-а нет намеренно: тихий откат означал бы
вторую копию правил экранирования.
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
    from vortex_chat import Naive
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = ["Naive"]
