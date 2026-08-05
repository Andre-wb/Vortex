"""
app/security/secret_rotation.py — плановая ротация секретов stealth level 4.

Секреты протоколов (ShadowTLS, Trojan) и облачных релеев живут в .env и
переживают рестарт. Раз в SECRET_ROTATION_HOURS каждый из них заменяется новым
значением, а предыдущее сохраняется в <KEY>_PREV и остаётся валидным ещё одно
окно — клиенты и уже задеплоенные Worker/Lambda/Function продолжают работать,
пока оператор не разнесёт новое значение.

Значения, заданные оператором в окружении процесса (Docker, systemd, shell),
считаются управляемыми извне и не ротируются.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from typing import TYPE_CHECKING

from app.config import (
    NAIVE_PROBE_DOMAINS,
    Config,
    env_upsert,
    is_externally_set,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

PREV_SUFFIX = "_PREV"
ROTATED_AT_KEY = "SECRETS_ROTATED_AT"

# Ротируемые ключи и фабрики новых значений. Имена совпадают с атрибутами
# Config, поэтому после ротации атрибуты обновляются тем же ключом.
ROTATABLE: dict[str, Callable[[], str]] = {
    "SHADOWTLS_PASSWORD": lambda: secrets.token_hex(32),
    "TROJAN_PASSWORD": lambda: secrets.token_hex(32),
    "CDN_WORKER_KV_SECRET": lambda: secrets.token_hex(32),
    "AWS_RELAY_SECRET": lambda: secrets.token_hex(32),
    "AZURE_RELAY_SECRET": lambda: secrets.token_hex(32),
    "NAIVE_USERNAME": lambda: secrets.token_hex(8),
    "NAIVE_PASSWORD": lambda: secrets.token_urlsafe(24),
    "NAIVE_PROBE_DOMAIN": lambda: secrets.choice(NAIVE_PROBE_DOMAINS),
}

_reload_hooks: list[Callable[[], None]] = []


def register_reload_hook(hook: Callable[[], None]) -> None:
    """Регистрирует callback, вызываемый после ротации (перечитать секреты)."""
    if hook not in _reload_hooks:
        _reload_hooks.append(hook)


def current(key: str) -> str:
    """Действующее значение секрета."""
    return os.getenv(key, "")


def previous(key: str) -> str:
    """Предыдущее значение секрета — принимается до следующей ротации."""
    return os.getenv(key + PREV_SUFFIX, "")


def last_rotation_ts() -> float:
    try:
        return float(os.getenv(ROTATED_AT_KEY, "0") or 0)
    except ValueError:
        return 0.0


def rotate_all() -> list[str]:
    """
    Ротирует все автогенерированные level4-секреты.
    Возвращает список ключей, которые были заменены.
    """
    rotated: list[str] = []
    for key, factory in ROTATABLE.items():
        if is_externally_set(key):
            continue
        old = current(key)
        new = factory()
        if old:
            env_upsert(key + PREV_SUFFIX, old)
        env_upsert(key, new)
        setattr(Config, key, new)
        rotated.append(key)

    env_upsert(ROTATED_AT_KEY, str(int(time.time())))

    if rotated:
        for hook in _reload_hooks:
            try:
                hook()
            except Exception as e:
                logger.warning("secret rotation reload hook failed: %s", e)
        logger.info("Secret rotation: rotated %d level4 secrets", len(rotated))
    else:
        logger.info("Secret rotation: nothing to rotate (all values set externally)")
    return rotated


class SecretRotator:
    """Фоновая задача, ротирующая секреты по расписанию."""

    def __init__(self):
        self._task: asyncio.Task | None = None

    @property
    def interval_seconds(self) -> float:
        return Config.SECRET_ROTATION_HOURS * 3600

    def _seconds_until_next(self) -> float:
        last = last_rotation_ts()
        if not last:
            # Первый запуск: точку отсчёта фиксируем, но секреты не трогаем —
            # они только что сгенерированы.
            env_upsert(ROTATED_AT_KEY, str(int(time.time())))
            return self.interval_seconds
        return max(0.0, last + self.interval_seconds - time.time())

    async def start(self) -> None:
        if Config.SECRET_ROTATION_HOURS <= 0:
            logger.info("Secret rotation: disabled (SECRET_ROTATION_HOURS<=0)")
            return
        if Config.TESTING:
            return
        if self._task and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="secret-rotation")

    def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._seconds_until_next())
                if rotate_all():
                    await self._redeploy_relays()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Secret rotation loop stopped: %s", e)

    async def _redeploy_relays(self) -> None:
        """
        Разносит новые секреты по релеям.

        Дедлайн — оставшаяся часть окна: пока оно не закрылось, релеи всё ещё
        принимают прежний секрет, после — перестают.
        """
        try:
            from app.transport.relay_deploy import deploy_all_with_retry
        except Exception as e:
            logger.warning("Relay deploy unavailable: %s", e)
            return
        await deploy_all_with_retry(self.interval_seconds)

    def get_status(self) -> dict:
        last = last_rotation_ts()
        return {
            "enabled": Config.SECRET_ROTATION_HOURS > 0,
            "interval_hours": Config.SECRET_ROTATION_HOURS,
            "running": bool(self._task and not self._task.done()),
            "last_rotation": int(last) if last else None,
            "next_rotation": int(last + self.interval_seconds) if last else None,
            "rotatable_keys": sorted(
                k for k in ROTATABLE if not is_externally_set(k)
            ),
        }


rotator = SecretRotator()


def rotation_status() -> dict:
    """Состояние плановой ротации."""
    return rotator.get_status()
