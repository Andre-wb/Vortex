"""Загрузка Rust-разборщика конверта сообщения.

Границы шифротекста, строгий hex, версия конверта, окно клиентской метки времени,
упоминания, тексты и коды отказов, а также формы исходящих конвертов живут в крейте
`vortex-proto` и выставлены в Python через `vortex_chat`. Здесь только загрузка
расширения — Python-fallback-а нет намеренно: вторая копия правил формата означала
бы дрейф между рантаймами.
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
        MESSAGE_LIMITS,
        message_ack,
        message_ack_duplicate,
        message_client_stamp,
        message_deleted,
        message_edited,
        message_enc_version,
        message_frame_too_large,
        message_read,
        message_sent,
        message_stored,
        message_thread_sent,
        message_thread_update,
        message_wire_stamp,
    )
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = [
    "MESSAGE_LIMITS",
    "message_ack",
    "message_ack_duplicate",
    "message_client_stamp",
    "message_deleted",
    "message_edited",
    "message_enc_version",
    "message_frame_too_large",
    "message_read",
    "message_sent",
    "message_stored",
    "message_thread_sent",
    "message_thread_update",
    "message_wire_stamp",
]
