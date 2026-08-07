"""Загрузка Rust-реализации Blind Mailbox Protocol.

Протокол целиком живёт в крейте `vortex-bmp` и выставлен в Python через
`vortex_chat`: хранилище ящиков, деривация идентификаторов, ограничение частоты,
секреты комнат, уборка просроченных сообщений и пределы. Python отвечает только
за HTTP.
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
    import vortex_chat as _rust
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

LIMITS: dict = _rust.BMP_LIMITS

connect_redis = _rust.bmp_connect_redis
is_shared = _rust.bmp_is_shared
deposit = _rust.bmp_deposit
fetch_batch = _rust.bmp_fetch_batch
collect_garbage = _rust.bmp_gc
stats = _rust.bmp_stats
set_room_secret = _rust.bmp_set_room_secret
get_room_secret = _rust.bmp_get_room_secret
remove_room_secret = _rust.bmp_remove_room_secret
deposit_envelope = _rust.bmp_deposit_envelope
start_garbage_collector = _rust.bmp_start_gc
compute_mailbox_id = _rust.bmp_compute_mailbox_id
compute_mailbox_ids = _rust.bmp_compute_mailbox_ids
pair_jitter = _rust.bmp_pair_jitter
wake_category = _rust.bmp_wake_category

logger.info(
    "✅ BMP (Rust) загружен — TTL=%dс, батч=%d, ящиков=%d",
    LIMITS["ttl_seconds"],
    LIMITS["max_batch"],
    LIMITS["max_mailboxes"],
)


def use_shared_state() -> bool:
    """
    Перевести сторы BMP в Redis, если он настроен.

    Без `REDIS_URL` состояние остаётся в памяти процесса — как и весь остальной
    проект в однопроцессном режиме. Вызывать до приёма трафика: переключение
    заменяет хранилище, и сообщения, положенные до вызова, останутся в памяти.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[BMP] Redis не настроен — состояние в памяти процесса")
        return False

    try:
        connected = connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.warning("[BMP] Redis недоступен (%s) — состояние в памяти процесса", error)
        return False

    if connected:
        logger.info("[BMP] состояние в Redis — ящики видны всем воркерам")
    return connected


__all__ = [
    "LIMITS",
    "collect_garbage",
    "compute_mailbox_id",
    "compute_mailbox_ids",
    "connect_redis",
    "deposit",
    "deposit_envelope",
    "fetch_batch",
    "get_room_secret",
    "is_shared",
    "pair_jitter",
    "remove_room_secret",
    "set_room_secret",
    "start_garbage_collector",
    "stats",
    "use_shared_state",
    "wake_category",
]
