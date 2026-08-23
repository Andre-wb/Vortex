"""Загрузка Rust-реализации состояния доставки сообщений.

Память о повторах (`msg_id`), очередь сообщений для офлайн-участников комнаты и
очередь уведомлений живут в крейте `vortex-delivery` и выставлены в Python
через `vortex_chat`. Пределы, сроки жизни, порядок выдачи и вытеснение при
переполнении принадлежат Rust; Python отвечает за WebSocket и рассылку.

Поведение при недоступном Redis выбрано владельцем 2026-08-22: **строго
fail-closed на всех трёх сторах**, включая проверку на повтор. Без общего
состояния узел не принимает сообщение, а не делает вид, что запомнил его или
поставил в очередь. Цена принята сознательно: при отказе Redis чат перестаёт
принимать сообщения целиком. Состояния в памяти воркера при заданном
`REDIS_URL` нет ни в каком виде — оно и есть тот split-brain, ради устранения
которого сторы переносились.

База часов сменилась с монотонной на настенную. `time.monotonic()` считает от
старта процесса, и в общем сторе такое число не значит ничего: сроки жизни
записей теперь считаются от эпохи Unix. Наблюдаемое следствие — записи
переживают перезапуск воркера и продолжают стареть по настенным часам, а не
обнуляются вместе с процессом.
"""

from __future__ import annotations

import json
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


class DeliveryUnavailableError(RuntimeError):
    """Общее состояние доставки недоступно — операция не выполнена."""


def _guard(call, *args):
    try:
        return call(*args)
    except DeliveryUnavailableError:
        raise
    except RuntimeError as error:
        raise DeliveryUnavailableError(str(error)) from error


mode = _rust.delivery_mode
is_shared = _rust.delivery_is_shared


def is_repeat(msg_id: str) -> bool:
    return _guard(_rust.delivery_is_repeat, msg_id)


def seen_count() -> int:
    return _guard(_rust.delivery_seen_count)


def room_deposit(room_id: int, user_ids: list[int], payload: dict) -> None:
    if not user_ids:
        return
    _guard(_rust.delivery_room_deposit, room_id, user_ids, json.dumps(payload))


def room_collect(room_id: int, user_id: int) -> list[dict[str, Any]]:
    rows = _guard(_rust.delivery_room_collect, room_id, user_id)
    return [json.loads(row) for row in rows]


def room_sweep() -> int:
    return _guard(_rust.delivery_room_sweep)


def room_tally() -> dict[str, int]:
    queues, total = _guard(_rust.delivery_room_tally)
    return {"queues": queues, "total_pending": total}


def notification_deposit(user_id: int, payload: dict) -> None:
    _guard(_rust.delivery_notification_deposit, user_id, json.dumps(payload))


def notification_collect(user_id: int) -> list[dict[str, Any]]:
    rows = _guard(_rust.delivery_notification_collect, user_id)
    return [json.loads(row) for row in rows]


def notification_tally() -> dict[str, int]:
    queues, total = _guard(_rust.delivery_notification_tally)
    return {"queues": queues, "total": total}


def use_shared_state() -> bool:
    """
    Перевести состояние доставки в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` состояние остаётся в памяти
    процесса — это однопроцессный режим. Если `REDIS_URL` задан, но Redis
    недоступен, состояние **не** уходит в память: стор запечатывается, и приём
    сообщений отказывает, пока узел не перезапустят с живым Redis.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[delivery] Redis не настроен — состояние доставки в памяти процесса")
        return False

    try:
        connected = _rust.delivery_connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error("[delivery] Redis недоступен (%s) — доставка отказывает", error)
        return False

    if connected:
        logger.info("[delivery] состояние доставки в Redis — действует во всех воркерах")
    return connected
