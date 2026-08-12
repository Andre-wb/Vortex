"""Загрузка Rust-реализации механизмов Level 3.

Обнаружение активного зондирования, порядок заголовков Chrome, куки-банка,
цепочка Referer, генератор резервных доменов, gzip-конверт, формат провода DNS,
туннель DoH и расписания (пачки, потери пакетов, ротация ключей) живут в крейте
`vortex-transport` и выставлены в Python через `vortex_chat`. Здесь только
загрузка расширения — Python-fallback-а нет намеренно: тихий откат означал бы
вторую копию правил, по которым запрос признаётся зондом, и второй формат
провода у DNS.
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
        BurstPlan,
        CookieJar,
        DohTunnel,
        DomainGenerator,
        EntropyEnvelope,
        PacketLoss,
        ProbeDetector,
        RefererChain,
        RotationSchedule,
        chrome_headers,
        dns_addresses,
        dns_query,
        header_order,
    )
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = [
    "BurstPlan",
    "CookieJar",
    "DohTunnel",
    "DomainGenerator",
    "EntropyEnvelope",
    "PacketLoss",
    "ProbeDetector",
    "RefererChain",
    "RotationSchedule",
    "chrome_headers",
    "dns_addresses",
    "dns_query",
    "header_order",
]
