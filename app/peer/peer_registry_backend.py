"""Загрузка Rust-реализации реестра узлов.

Реестр живёт в крейте `vortex-net` и выставлен в Python через `vortex_chat`.
До этого среза реестров было **два**: `PeerStore` внутри UDP-обнаружения и
Python-словарь `PeerRegistry`, который синхронизировался из первого опросом
раз в три секунды. Теперь он один: и UDP-служба, и Python пишут в общий стор,
опрос удалён вместе с трёхсекундной задержкой появления узла.

Правила принадлежат Rust: разбор IP-адреса, диапазон порта, длина и алфавит
имени, форма ключа узла (64 hex), «жив ли узел» по таймауту, сохранение
ранее известного ключа при молчаливом обновлении и уборка мёртвых записей.
Python отвечает за HTTP, опрос комнат соседей и шифрование обмена.

Поведение при недоступном Redis выбрано владельцем 2026-08-22: **строго
fail-closed**. Без общего состояния узел не отдаёт список соседей, а не
показывает пустой.

База часов сменилась с монотонной на настенную — монотонная метка в общем
сторе не значит ничего.

Собственный адрес узла (`own_address`) остаётся процесс-локальным: его
определяет UDP-служба этого процесса, и для соседнего воркера он был бы
чужим ответом, а не общим состоянием.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

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


class PeerRegistryUnavailableError(RuntimeError):
    """Общий реестр узлов недоступен — операция не выполнена."""


def _guard(call, *args):
    try:
        return call(*args)
    except PeerRegistryUnavailableError:
        raise
    except ValueError:
        raise
    except RuntimeError as error:
        raise PeerRegistryUnavailableError(str(error)) from error


mode = _rust.registry_mode
is_shared = _rust.registry_is_shared
set_timeout = _rust.registry_set_timeout
own_address = _rust.registry_own_address
set_own_address = _rust.registry_set_own_address


def heard(address: str, name: str, port: int, pubkey: Optional[str] = None) -> bool:
    return _guard(_rust.registry_heard, address, name, port, pubkey)


def find(address: str) -> Optional[dict[str, Any]]:
    return _guard(_rust.registry_find, address)


def alive() -> list[dict[str, Any]]:
    return _guard(_rust.registry_alive)


def forget_dead() -> int:
    return _guard(_rust.registry_forget_dead)


def set_rooms(address: str, document: str) -> None:
    _guard(_rust.registry_set_rooms, address, document)


def rooms_of_the_living() -> list[tuple[str, str, int, str]]:
    return _guard(_rust.registry_rooms_of_the_living)


def count() -> int:
    return _guard(_rust.registry_count)


def next_virtual_room() -> int:
    """Выдаёт очередной номер федеративной комнаты из общего счётчика."""
    return _guard(_rust.registry_next_virtual_room)


def reserve_virtual_room(taken: int) -> None:
    """Сдвигает общий счётчик ниже уже занятого номера."""
    _guard(_rust.registry_reserve_virtual_room, taken)


def use_shared_state() -> bool:
    """
    Перевести реестр узлов в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` реестр остаётся в памяти
    процесса — это однопроцессный режим. Если `REDIS_URL` задан, но Redis
    недоступен, реестр **не** уходит в память: стор запечатывается, и
    обращения к списку соседей отказывают, пока узел не перезапустят с живым
    Redis.
    """
    from app.config import Config

    set_timeout(float(getattr(Config, "PEER_TIMEOUT_SEC", 15)))

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[peers] Redis не настроен — реестр узлов в памяти процесса")
        return False

    try:
        connected = _rust.registry_connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error("[peers] Redis недоступен (%s) — реестр узлов отказывает", error)
        return False

    if connected:
        logger.info("[peers] реестр узлов в Redis — действует во всех воркерах")
    return connected


__all__ = [
    "PeerRegistryUnavailableError",
    "alive",
    "count",
    "find",
    "forget_dead",
    "heard",
    "is_shared",
    "mode",
    "next_virtual_room",
    "own_address",
    "reserve_virtual_room",
    "rooms_of_the_living",
    "set_own_address",
    "set_rooms",
    "set_timeout",
    "use_shared_state",
]
