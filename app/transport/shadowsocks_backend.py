"""Загрузка Rust-реализации Shadowsocks.

Формат провода v2 (пролог-соль, кадр `AEAD(длина) ‖ AEAD(тело)`, назначение
с паддингом в первом кадре), реестр паролей и разбор адреса живут в крейте
`vortex-transport` и выставлены в Python через `vortex_chat`. Здесь только
загрузка расширения — Python-fallback-а нет намеренно: тихий откат означал бы
вторую копию формата и вторую копию правил разбора адреса.
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
    from vortex_chat import Shadowsocks
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = ["Shadowsocks"]
