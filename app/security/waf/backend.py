"""Загрузка Rust-движка WAF.

Движок целиком живёт в крейте `vortex_waf`: правила, разбор тела, ограничение
частоты, блокировки, капча. Python-слой отвечает только за ASGI и HTTP.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_BUILD_HINT = (
    "Модуль vortex_waf не установлен. Соберите расширение:\n"
    "    make waf-build\n"
    "или вручную:\n"
    "    cd vortex_waf && maturin develop --release"
)

try:
    import vortex_waf as _rust
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

VERSION: str = _rust.VERSION
RULE_COUNT: int = _rust.RULE_COUNT

# Движок и разрешение адреса источника берутся из Rust как есть.
WAFEngine = _rust.WafEngine
resolve_client_ip = _rust.resolve_client_ip

logger.info("✅ vortex_waf %s (Rust) загружен — правил: %d", VERSION, RULE_COUNT)

__all__ = ["VERSION", "RULE_COUNT", "WAFEngine", "resolve_client_ip"]
