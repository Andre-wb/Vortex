"""Загрузка Rust-реализации реестра пуш-прокси BMP.

Регистрации пуш-токенов по категориям (0..255) живут в крейте `vortex-bmp`
и выставлены в Python через `vortex_chat`. Срок жизни токена, предел на
категорию, вытеснение и счёт побудок принадлежат Rust; Python отвечает за
HTTP, проверку адреса доставки и саму отправку Web Push.

Поведение при недоступном Redis выбрано владельцем 2026-08-22: **строго
fail-closed**. Без общего состояния узел не принимает регистрацию и не
рассылает побудку, а не делает вид, что запомнил токен.

Приватность реестра не меняется: категория по-прежнему единственное, что о
подписчике знает прокси.
"""

from __future__ import annotations

import logging
from typing import Any

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


class PushRegistryUnavailableError(RuntimeError):
    """Общее состояние пуш-прокси недоступно — операция не выполнена."""


def _guard(call, *args):
    try:
        return call(*args)
    except PushRegistryUnavailableError:
        raise
    except ValueError:
        raise
    except RuntimeError as error:
        raise PushRegistryUnavailableError(str(error)) from error


mode = _rust.push_mode
is_shared = _rust.push_is_shared


def register(categories: list[int], token: str, endpoint: str) -> None:
    _guard(_rust.push_register, list(categories), token, endpoint)


def unregister(token: str) -> int:
    return _guard(_rust.push_unregister, token)


def wake(category: int) -> list[tuple[str, str]]:
    return _guard(_rust.push_wake, category)


def registrations(category: int) -> list[tuple[str, str]]:
    return _guard(_rust.push_registrations, category)


def tally() -> dict[str, Any]:
    return _guard(_rust.push_tally)


def use_shared_state() -> bool:
    """
    Перевести реестр пуш-прокси в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` реестр остаётся в памяти
    процесса — это однопроцессный режим. Если `REDIS_URL` задан, но Redis
    недоступен, реестр **не** уходит в память: стор запечатывается, и
    регистрация с побудкой отказывают, пока узел не перезапустят с живым Redis.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[push-proxy] Redis не настроен — реестр пушей в памяти процесса")
        return False

    try:
        connected = _rust.push_connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error("[push-proxy] Redis недоступен (%s) — пуш-прокси отказывает", error)
        return False

    if connected:
        logger.info("[push-proxy] реестр пушей в Redis — действует во всех воркерах")
    return connected


__all__ = [
    "PushRegistryUnavailableError",
    "is_shared",
    "mode",
    "register",
    "registrations",
    "tally",
    "unregister",
    "use_shared_state",
    "wake",
]
