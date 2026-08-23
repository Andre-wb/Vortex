"""Загрузка Rust-разборщика pre-key бандлов.

Формат бандла (hex, длины ключей, пределы пачек), проверка подписей SPK,
привязки identity_key и Kyber pre-key, а также форма ответов живут в крейте
`vortex-proto` и выставлены в Python через `vortex_chat`. Здесь только загрузка
расширения — Python-fallback-а нет намеренно: вторая копия правил формата
означала бы дрейф между рантаймами.
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
        PREKEY_LIMITS,
        StoredPreKeyBundle,
        prekey_bundle_list,
        prekey_bundle_response,
        prekey_claim_response,
        prekey_client_device_id,
        prekey_needs_replenishment,
        prekey_parse_publish,
        prekey_status_published,
        prekey_status_unpublished,
    )
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = [
    "PREKEY_LIMITS",
    "StoredPreKeyBundle",
    "prekey_bundle_list",
    "prekey_bundle_response",
    "prekey_claim_response",
    "prekey_client_device_id",
    "prekey_needs_replenishment",
    "prekey_parse_publish",
    "prekey_status_published",
    "prekey_status_unpublished",
]
