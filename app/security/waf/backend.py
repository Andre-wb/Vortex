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
connect_redis = _rust.connect_redis
is_shared = _rust.is_shared


def use_shared_state() -> bool:
    """
    Перевести блокировки и историю обращений в Redis, если он настроен.

    Вызывать до создания движка: сторы подставляются при сборке. Без
    `REDIS_URL` состояние остаётся в памяти процесса, при недоступности Redis
    движок соберётся на памяти и запишет предупреждение.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[WAF] Redis не настроен — блокировки в памяти процесса")
        return False

    try:
        connected = connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.warning("[WAF] Redis недоступен (%s) — блокировки в памяти процесса", error)
        return False

    if connected:
        logger.info("[WAF] блокировки и лимиты в Redis — действуют во всех воркерах")
    return connected


logger.info("✅ vortex_waf %s (Rust) загружен — правил: %d", VERSION, RULE_COUNT)

__all__ = [
    "RULE_COUNT",
    "VERSION",
    "WAFEngine",
    "connect_redis",
    "is_shared",
    "resolve_client_ip",
    "use_shared_state",
]
