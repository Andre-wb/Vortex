"""Загрузка Rust-реализации состояния живых сессий.

Голосовые каналы, сцена, отметка записи, групповые звонки и трансляции живут в
крейте `vortex-live` и выставлены в Python через `vortex_chat`. Формат записей,
сроки жизни, переходы состояний и формы ответов принадлежат Rust; Python
отвечает за HTTP, WebSocket и обращения к базе.

Поведение при недоступном Redis выбрано владельцем 2026-08-20 и совпадает со
срезами 3–5: нет общего состояния — нет живой сессии. Любая операция отвечает
`LiveUnavailableError`, который `app/main.py` превращает в 503. Состояния в
памяти воркера при заданном `REDIS_URL` нет ни в каком виде — оно и есть та
неточность, ради устранения которой сторы переносились.

Срок жизни записи — 120 секунд, продление — 30 секунд: WS-циклы голоса и
трансляции принимают сообщение с тайм-аутом и по нему продлевают запись.
Решение владельца 2026-08-20.
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

RENEWAL_SECONDS = 30


class LiveUnavailableError(RuntimeError):
    """Общее состояние живых сессий недоступно — операция не выполнена."""


def _guard(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except LiveUnavailableError:
        raise
    except RuntimeError as error:
        raise LiveUnavailableError(str(error)) from error


Identity = tuple[int, str, Optional[str], Optional[str], Optional[str]]


def identity_of(user) -> Identity:
    return (
        user.id,
        user.username,
        user.display_name,
        user.avatar_emoji,
        user.avatar_url,
    )


mode = _rust.live_mode
is_shared = _rust.live_is_shared


def voice_join(room_id: int, user) -> dict:
    return _guard(_rust.live_voice_join, room_id, identity_of(user))


def voice_leave(room_id: int, user_id: int) -> dict:
    return _guard(_rust.live_voice_leave, room_id, user_id)


def voice_participants(room_id: int) -> list[dict]:
    return _guard(_rust.live_voice_participants, room_id)


def voice_count(room_id: int) -> int:
    return _guard(_rust.live_voice_count, room_id)


def voice_find(room_id: int, user_id: int) -> Optional[dict]:
    return _guard(_rust.live_voice_find, room_id, user_id)


def voice_mute(room_id: int, user_id: int, is_muted=None, is_video=None) -> Optional[dict]:
    return _guard(_rust.live_voice_mute, room_id, user_id, is_muted, is_video)


def voice_renew(room_id: int, user_id: int) -> bool:
    return _guard(_rust.live_voice_renew, room_id, user_id)


def stage_open(room_id: int, user_id: int) -> list[int]:
    return _guard(_rust.live_stage_open, room_id, user_id)


def stage_close(room_id: int) -> bool:
    return _guard(_rust.live_stage_close, room_id)


def stage_status(room_id: int, user_id: int) -> dict:
    return _guard(_rust.live_stage_status, room_id, user_id)


def stage_add(room_id: int, user_id: int) -> Optional[list[int]]:
    return _guard(_rust.live_stage_add, room_id, user_id)


def stage_remove(room_id: int, user_id: int) -> Optional[list[int]]:
    return _guard(_rust.live_stage_remove, room_id, user_id)


def recording_start(room_id: int, user_id: int) -> dict:
    return _guard(_rust.live_recording_start, room_id, user_id)


def recording_stop(room_id: int) -> dict:
    return _guard(_rust.live_recording_stop, room_id)


def recording_status(room_id: int) -> dict:
    return _guard(_rust.live_recording_status, room_id)


def call_start(
    room_id: int,
    initiator_id: int,
    call_type: str,
    members: list[Identity],
    sfu_available: bool,
    threshold: int,
    sfu_max: int,
) -> dict:
    return _guard(
        _rust.live_call_start,
        room_id,
        initiator_id,
        call_type,
        members,
        sfu_available,
        threshold,
        sfu_max,
    )


def call_join(call_id: str, user_id: int) -> dict:
    return _guard(_rust.live_call_join, call_id, user_id)


def call_decline(call_id: str, user_id: int) -> str:
    return _guard(_rust.live_call_decline, call_id, user_id)


def call_leave(call_id: str, user_id: int) -> dict:
    return _guard(_rust.live_call_leave, call_id, user_id)


def call_add(call_id: str, actor_id: int, user) -> dict:
    return _guard(_rust.live_call_add, call_id, actor_id, identity_of(user))


def call_end(call_id: str, actor_id: int) -> dict:
    return _guard(_rust.live_call_end, call_id, actor_id)


def call_ring_out(call_id: str) -> Optional[dict]:
    return _guard(_rust.live_call_ring_out, call_id)


def call_status(call_id: str) -> Optional[dict]:
    return _guard(_rust.live_call_status, call_id)


def call_active(room_id: int) -> Optional[dict]:
    return _guard(_rust.live_call_active, room_id)


def call_renew(call_id: str) -> bool:
    return _guard(_rust.live_call_renew, call_id)


def stream_open(
    room_id: int,
    host,
    title: str,
    description: str,
    allow_reactions: bool,
    allow_donations: bool,
    donation_card: str,
    donation_message: str,
    auto_accept_speakers: bool,
) -> dict:
    return _guard(
        _rust.live_stream_open,
        room_id,
        identity_of(host),
        title,
        description,
        allow_reactions,
        allow_donations,
        donation_card,
        donation_message,
        auto_accept_speakers,
    )


def stream_stop(room_id: int) -> dict:
    return _guard(_rust.live_stream_stop, room_id)


def stream_join(room_id: int, user, runs_the_room: bool) -> dict:
    return _guard(_rust.live_stream_join, room_id, identity_of(user), runs_the_room)


def stream_leave(room_id: int, user_id: int) -> dict:
    return _guard(_rust.live_stream_leave, room_id, user_id)


def stream_status(room_id: int) -> Optional[dict]:
    return _guard(_rust.live_stream_status, room_id)


def stream_raise_hand(room_id: int, user_id: int) -> dict:
    return _guard(_rust.live_stream_raise_hand, room_id, user_id)


def stream_lower_hand(room_id: int, user_id: int) -> dict:
    return _guard(_rust.live_stream_lower_hand, room_id, user_id)


def stream_hands(room_id: int) -> Optional[list[dict]]:
    return _guard(_rust.live_stream_hands, room_id)


def stream_grant(
    room_id: int,
    actor_id: int,
    target_id: int,
    role: Optional[str] = None,
    can_speak: Optional[bool] = None,
    can_video: Optional[bool] = None,
    can_screen_share: Optional[bool] = None,
) -> dict:
    return _guard(
        _rust.live_stream_grant,
        room_id,
        actor_id,
        target_id,
        role,
        can_speak,
        can_video,
        can_screen_share,
    )


def stream_kick(room_id: int, actor_id: int, target_id: int) -> dict:
    return _guard(_rust.live_stream_kick, room_id, actor_id, target_id)


def stream_react(room_id: int, user_id: int, emoji: str) -> dict:
    return _guard(_rust.live_stream_react, room_id, user_id, emoji)


def stream_donate(room_id: int, user_id: int, amount: str, currency: str, message: str) -> dict:
    return _guard(_rust.live_stream_donate, room_id, user_id, amount, currency, message)


def stream_update(room_id: int, actor_id: int, **patch: Any) -> dict:
    return _guard(_rust.live_stream_update, room_id, actor_id, **patch)


def stream_mute(room_id: int, user_id: int, is_muted=None, is_video_on=None) -> dict:
    return _guard(_rust.live_stream_mute, room_id, user_id, is_muted, is_video_on)


def stream_share_screen(room_id: int, user_id: int, sharing: bool) -> dict:
    return _guard(_rust.live_stream_share_screen, room_id, user_id, sharing)


def stream_renew(room_id: int) -> bool:
    return _guard(_rust.live_stream_renew, room_id)


def schedule_plan(
    room_id: int, title: str, scheduled_at: str, host_id: int, host_name: str
) -> Optional[dict]:
    return _guard(_rust.live_schedule_plan, room_id, title, scheduled_at, host_id, host_name)


def schedule_find(room_id: int) -> Optional[dict]:
    return _guard(_rust.live_schedule_find, room_id)


def schedule_forget(room_id: int) -> bool:
    return _guard(_rust.live_schedule_forget, room_id)


def schedule_claim_due() -> Optional[dict]:
    return _guard(_rust.live_schedule_claim_due)


def use_shared_state() -> bool:
    """
    Перевести состояние живых сессий в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` состояние остаётся в памяти
    процесса — это однопроцессный режим. Если `REDIS_URL` задан, но Redis
    недоступен, состояние **не** уходит в память: стор запечатывается, и все
    роуты голоса, звонков и трансляций отвечают 503, пока узел не перезапустят
    с живым Redis.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[live] Redis не настроен — состояние живых сессий в памяти процесса")
        return False

    try:
        connected = _rust.live_connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error("[live] Redis недоступен (%s) — живые сессии отказывают", error)
        return False

    if connected:
        logger.info("[live] состояние живых сессий в Redis — действует во всех воркерах")
    return connected
