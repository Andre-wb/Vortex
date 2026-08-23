"""Загрузка Rust-реализации состояния возобновления.

Сессии дозагрузки файла (`/api/files/upload-*`) и курсоры переноса сеанса
(`/api/session/cursor`, `/api/session/handoff/*`) живут в крейте
`vortex-resume` и выставлены в Python через `vortex_chat`. Сроки жизни,
пределы, план кусков, порядок выдачи и правила курсора принадлежат Rust;
Python отвечает за HTTP, файловую систему и БД.

Поведение при недоступном Redis выбрано владельцем 2026-08-22: **строго
fail-closed на обоих сторах**, как в срезе 8. Без общего состояния узел не
принимает дозагрузку и не сохраняет курсор, а не делает вид, что запомнил их.

База часов у сессий дозагрузки сменилась с монотонной на настенную:
`time.monotonic()` считает от старта процесса, и в общем сторе такое число не
значит ничего. Наблюдаемое следствие — сессия переживает перезапуск воркера и
продолжает стареть по настенным часам, а не обнуляется вместе с процессом.

Куски файла остаются на файловой системе (`UPLOAD_DIR/_chunks/<upload_id>`) —
в поставляемой конфигурации это общий том `vortex-uploads`, смонтированный во
все варианты сервиса, поэтому воркеры видят одни и те же файлы. При
развёртывании на несколько хостов без общего тома перенос сессий в Redis
разделения не снимает: метаданные найдутся, а куски — нет.
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


class ResumeUnavailableError(RuntimeError):
    """Общее состояние возобновления недоступно — операция не выполнена."""


def _guard(call, *args):
    try:
        return call(*args)
    except ResumeUnavailableError:
        raise
    except ValueError:
        raise
    except RuntimeError as error:
        raise ResumeUnavailableError(str(error)) from error


mode = _rust.resume_mode
is_shared = _rust.resume_is_shared


def upload_limits() -> dict[str, Any]:
    return _rust.resume_upload_limits()


def upload_plan(file_size: int, chunk_size: int) -> tuple[int, int]:
    return _rust.resume_upload_plan(file_size, chunk_size)


def upload_open(
    upload_id: str,
    room_id: int,
    user_id: int,
    file_name: str,
    file_size: int,
    total_chunks: int,
    file_hash: str,
) -> None:
    _guard(
        _rust.resume_upload_open,
        upload_id,
        room_id,
        user_id,
        file_name,
        file_size,
        total_chunks,
        file_hash,
    )


def upload_find(upload_id: str) -> dict[str, Any]:
    return _guard(_rust.resume_upload_find, upload_id)


def upload_receive(upload_id: str, chunk_index: int) -> dict[str, Any]:
    return _guard(_rust.resume_upload_receive, upload_id, chunk_index)


def upload_close(upload_id: str) -> bool:
    return _guard(_rust.resume_upload_close, upload_id)


def upload_sweep() -> list[str]:
    return _guard(_rust.resume_upload_sweep)


def upload_count() -> int:
    return _guard(_rust.resume_upload_count)


def cursor_save(user_pubkey: str, last_bmp_ts: float, rooms: list[int]) -> dict[str, Any]:
    return _guard(_rust.resume_cursor_save, user_pubkey, float(last_bmp_ts), list(rooms))


def cursor_find(user_pubkey: str) -> Optional[dict[str, Any]]:
    return _guard(_rust.resume_cursor_find, user_pubkey)


def cursor_forget(user_pubkey: str) -> bool:
    return _guard(_rust.resume_cursor_forget, user_pubkey)


def cursor_count() -> int:
    return _guard(_rust.resume_cursor_count)


def use_shared_state() -> bool:
    """
    Перевести состояние возобновления в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` состояние остаётся в памяти
    процесса — это однопроцессный режим. Если `REDIS_URL` задан, но Redis
    недоступен, состояние **не** уходит в память: стор запечатывается, и
    дозагрузка с курсором отказывают, пока узел не перезапустят с живым Redis.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[resume] Redis не настроен — состояние возобновления в памяти процесса")
        return False

    try:
        connected = _rust.resume_connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error("[resume] Redis недоступен (%s) — возобновление отказывает", error)
        return False

    if connected:
        logger.info("[resume] состояние возобновления в Redis — действует во всех воркерах")
    return connected


__all__ = [
    "ResumeUnavailableError",
    "cursor_count",
    "cursor_find",
    "cursor_forget",
    "cursor_save",
    "is_shared",
    "mode",
    "upload_close",
    "upload_count",
    "upload_find",
    "upload_limits",
    "upload_open",
    "upload_plan",
    "upload_receive",
    "upload_sweep",
    "use_shared_state",
]
