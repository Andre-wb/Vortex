"""Загрузка Rust-аутентификатора REALITY.

Крипто-часть рукопожатия (X25519-ECDH → HKDF → AEAD-конверт), разбор
ClientHello, реестр short_id и защита от повтора живут в крейте
`vortex-transport` и выставлены в Python через `vortex_chat`. Здесь только
загрузка расширения — Python-fallback-а нет намеренно: тихий откат на
эталонную реализацию означал бы вторую копию security-логики.
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
    from vortex_chat import RealityAuth
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = ["RealityAuth"]
