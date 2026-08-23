"""Загрузка Rust-правил настроек и представления комнаты.

Пределы имени и описания, аватар по умолчанию, нормализация авто-удаления и
медленного режима, разбор антиспам-конфигурации, набор обоев и формат акцента,
режим репликации и форма ответа о комнате живут в крейте `vortex-proto` и
выставлены в Python через `vortex_chat`. Здесь только загрузка расширения —
Python-fallback-а нет намеренно.
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
        ROOM_LIMITS,
        room_antispam_config,
        room_avatar_given,
        room_description_read,
        room_name_read,
        room_replication_mode,
        room_settings_parse,
        room_theme,
        room_view,
    )
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

__all__ = [
    "ROOM_LIMITS",
    "room_antispam_config",
    "room_avatar_given",
    "room_description_read",
    "room_name_read",
    "room_replication_mode",
    "room_settings_parse",
    "room_theme",
    "room_view",
]
