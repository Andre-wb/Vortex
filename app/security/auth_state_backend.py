"""Загрузка Rust-реализации разделяемого состояния аутентификации.

Отзыв доступа, маркер первого фактора и защита handoff-токена от повтора живут в
крейте `vortex-auth` и выставлены в Python через `vortex_chat`: списки, сроки
жизни и решения принимает Rust, Python отвечает только за HTTP и за разбор
самого токена.

Поведение при недоступном Redis выбрано владельцем 2026-08-18: запись
(отзыв токена, выдача и сжигание маркера) отказывает, а чтение отвечает «не
отозван» / «маркера нет» — то есть отказ Redis не выкидывает всех из сеанса, но
и не создаёт вида, будто отзыв записан.

Защита от повтора — единственное исключение из «чтение отвечает нет»: там ответ
«повтора не было» без общего состояния означал бы принятый повторно токен,
поэтому и чтение, и запись отказывают (решение владельца 2026-08-19).

Счёт попыток аутентификации (`entry_*`, `totp_attempt_allowed`) устроен строже
всех остальных: без общего состояния попытка не разрешается вообще — решение
владельца 2026-08-20. Никакого счёта в памяти воркера здесь нет, поэтому при
мёртвом Redis все десять ограниченных точек входа отвечают 429, включая вход
по паролю.
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
    import vortex_chat as _rust
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc

connect_redis = _rust.auth_connect_redis
mode = _rust.auth_state_mode
is_shared = _rust.auth_state_is_shared
revoke_access = _rust.auth_revoke_access
access_revoked = _rust.auth_access_revoked
arm_password_marker = _rust.auth_arm_password_marker
password_marker_armed = _rust.auth_password_marker_armed
burn_password_marker = _rust.auth_burn_password_marker
entry_login_allowed = _rust.auth_entry_login_allowed
entry_register_allowed = _rust.auth_entry_register_allowed
totp_attempt_allowed = _rust.auth_totp_attempt_allowed
handoff_seen = _rust.auth_handoff_seen
handoff_accept = _rust.auth_handoff_accept
handoff_forget_all = _rust.auth_handoff_forget_all
handoff_token_seconds = _rust.auth_handoff_token_seconds
login_issue = _rust.auth_login_issue
login_issue_decoy = _rust.auth_login_issue_decoy
login_claim = _rust.auth_login_claim
qr_open = _rust.auth_qr_open
qr_answer = _rust.auth_qr_answer
qr_confirm = _rust.auth_qr_confirm
qr_hand_over = _rust.auth_qr_hand_over
passkey_open_registration = _rust.auth_passkey_open_registration
passkey_open_login = _rust.auth_passkey_open_login
passkey_claim_registration = _rust.auth_passkey_claim_registration
passkey_claim_login = _rust.auth_passkey_claim_login
wallet_issue = _rust.auth_wallet_issue
wallet_check = _rust.auth_wallet_check
wallet_burn = _rust.auth_wallet_burn


def use_shared_state() -> bool:
    """
    Перевести отзыв доступа и маркеры первого фактора в Redis, если он настроен.

    Вызывать до приёма трафика. Без `REDIS_URL` состояние остаётся в памяти
    процесса — это однопроцессный режим. Если `REDIS_URL` задан, но Redis
    недоступен, состояние **не** уходит в память: стор запечатывается, и запись
    отвечает ошибкой, пока узел не перезапустят с живым Redis.
    """
    from app.config import Config

    url = getattr(Config, "REDIS_URL", "") or ""
    if not url:
        logger.info("[auth] Redis не настроен — отзыв доступа в памяти процесса")
        return False

    try:
        connected = connect_redis(
            url,
            getattr(Config, "REDIS_POOL_SIZE", None),
            getattr(Config, "REDIS_CHANNEL_PREFIX", None) or None,
        )
    except RuntimeError as error:
        logger.error(
            "[auth] Redis недоступен (%s) — отзыв доступа и маркеры второго фактора отказывают",
            error,
        )
        return False

    if connected:
        logger.info("[auth] отзыв доступа и маркеры в Redis — действуют во всех воркерах")
    return connected


__all__ = [
    "access_revoked",
    "arm_password_marker",
    "burn_password_marker",
    "connect_redis",
    "entry_login_allowed",
    "entry_register_allowed",
    "handoff_accept",
    "handoff_forget_all",
    "handoff_seen",
    "handoff_token_seconds",
    "is_shared",
    "login_claim",
    "login_issue",
    "login_issue_decoy",
    "mode",
    "passkey_claim_login",
    "passkey_claim_registration",
    "passkey_open_login",
    "passkey_open_registration",
    "password_marker_armed",
    "qr_answer",
    "qr_confirm",
    "qr_hand_over",
    "qr_open",
    "revoke_access",
    "totp_attempt_allowed",
    "use_shared_state",
    "wallet_burn",
    "wallet_check",
    "wallet_issue",
]
