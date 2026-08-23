"""Загрузка Rust-реализации общего счёта обращений.

Тринадцать ограничителей частоты — транспортные пароли, пакеты сплетен, чтения
профиль-хранилища и уведомления zero-knowledge, переводы, предпросмотр ссылок,
помощник, конверты репликации, обращения узлов федерации, push-прокси,
раскрытие псевдонимов, гостевые входы федерации, сохранение долей ключа и
сигнальные сообщения — живут в крейте `vortex-ratelimit` и выставлены в Python
через `vortex_chat`. Пределы, окна и решение принимает Rust, Python отвечает
только за HTTP.

Поведение при недоступном Redis выбрано владельцем 2026-08-20 и совпадает со
срезом 3: без общего состояния попытку некому сосчитать, поэтому она не
разрешается. Счёта в памяти воркера при заданном `REDIS_URL` нет ни в каком
виде — он и есть та неточность, ради устранения которой сторы переносились.

Обход при `TESTING=true` — переменная окружения, а не правило домена, поэтому
он живёт здесь, а не в Rust. Прогон pytest идёт мимо ограничителей: одиннадцать
из тринадцати считают по адресу клиента, а у всех воркеров xdist он один
(`testclient`). Живые отказы закреплены отдельными проверками, которые снимают
флаг, — `app/tests/test_ratelimit_shared_state.py`.

Флуд-контроль комнат (`flood_*`) и антиспам (`repeat_spam`, `link_spam`)
устроены иначе и обхода не имеют: они считают по паре «комната+участник», а она
у каждого теста своя, и выключать их значило бы не проверять их вовсе.
Контракты при недоступном Redis у них при этом разные, оба выбраны владельцем:
флуд деградирует в память воркера (решение 2026-08-20 — сообщение, которое
некому сосчитать, доходит до комнаты), антиспам fail-closed (решение
2026-08-21 — сообщение, повторы которого некому сосчитать, задерживается).
Причина отказа возвращается наружу: предупреждение бота печатается только на
`spam`, а на `unavailable` сообщение молча не доходит.
"""

from __future__ import annotations

import logging
import os

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

_IS_TESTING = os.getenv("TESTING", "").lower() == "true"

connect_redis = _rust.ratelimit_connect_redis
mode = _rust.ratelimit_mode
is_shared = _rust.ratelimit_is_shared


def secrets_address_allowed(address: str, limit: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_secrets_address_allowed(address, limit)


def secrets_account_allowed(user_id: int, limit: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_secrets_account_allowed(user_id, limit)


def gossip_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_gossip_allowed(address)


def vault_read_allowed(user_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_vault_read_allowed(user_id)


def notification_sender_allowed(user_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_notification_sender_allowed(user_id)


def notification_pair_allowed(user_id: int, recipient_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_notification_pair_allowed(user_id, recipient_id)


def translation_allowed(user_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_translation_allowed(user_id)


def preview_account_allowed(user_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_preview_account_allowed(user_id)


def preview_address_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_preview_address_allowed(address)


def assistant_allowed(user_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_assistant_allowed(user_id)


def replication_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_replication_allowed(address)


def node_allowed(node: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_node_allowed(node)


def push_register_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_push_register_allowed(address)


def push_wake_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_push_wake_allowed(address)


def pseudonym_resolve_allowed(limit: int, window_seconds: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_pseudonym_resolve_allowed(limit, window_seconds)


def guest_login_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_guest_login_allowed(address)


def shard_store_allowed(address: str) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_shard_store_allowed(address)


def signal_allowed(user_id: int) -> bool:
    if _IS_TESTING:
        return True
    return _rust.ratelimit_signal_allowed(user_id)


def repeat_spam(room_id: int, user_id: int, text: str) -> tuple[bool, str]:
    """Сосчитать повтор сообщения: (задержать ли, причина)."""
    return _rust.ratelimit_repeat_spam(room_id, user_id, text)


def link_spam(room_id: int, user_id: int) -> tuple[bool, str]:
    """Сосчитать сообщение со ссылкой: (задержать ли, причина)."""
    return _rust.ratelimit_link_spam(room_id, user_id)


def flood_check(room_id: int, user_id: int, threshold: int) -> tuple[bool, int, bool]:
    """Сосчитать сообщение: (флудит ли, сколько срабатываний всего, пора ли банить)."""
    return _rust.ratelimit_flood_check(room_id, user_id, threshold)


def flood_forget(room_id: int, user_id: int) -> None:
    """Забыть окно сообщений участника — вызывается после наложенного наказания."""
    _rust.ratelimit_flood_forget(room_id, user_id)


def use_shared_state() -> bool:
    """
    Перевести счёт обращений в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` счёт остаётся в памяти процесса
    — это однопроцессный режим. Если `REDIS_URL` задан, но Redis недоступен,
    счёт **не** уходит в память: стор запечатывается, и все десять ограниченных
    точек отвечают отказом, пока узел не перезапустят с живым Redis.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[ratelimit] Redis не настроен — счёт обращений в памяти процесса")
        return False

    try:
        connected = connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error("[ratelimit] Redis недоступен (%s) — ограниченные точки отказывают", error)
        return False

    if connected:
        logger.info("[ratelimit] счёт обращений в Redis — действует во всех воркерах")
    return connected


__all__ = [
    "assistant_allowed",
    "connect_redis",
    "flood_check",
    "flood_forget",
    "gossip_allowed",
    "guest_login_allowed",
    "is_shared",
    "link_spam",
    "mode",
    "node_allowed",
    "notification_pair_allowed",
    "notification_sender_allowed",
    "preview_account_allowed",
    "preview_address_allowed",
    "pseudonym_resolve_allowed",
    "push_register_allowed",
    "push_wake_allowed",
    "repeat_spam",
    "replication_allowed",
    "secrets_account_allowed",
    "secrets_address_allowed",
    "shard_store_allowed",
    "signal_allowed",
    "translation_allowed",
    "use_shared_state",
    "vault_read_allowed",
]
