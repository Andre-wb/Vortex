"""Загрузка Rust-реализации ShadowTLS.

Ключевое расписание, распознавание switch-записи, разбор TLS-записей, выбор
донора по SNI и AEAD-поток данных живут в крейте `vortex-transport` и выставлены
в Python через `vortex_chat`. Здесь только загрузка расширения —
Python-fallback-а нет намеренно: тихий откат означал бы вторую копию
security-логики.
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
    from vortex_chat import ShadowTls
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = ["ShadowTls"]
