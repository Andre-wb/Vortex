"""
app/services/sealed_push.py — VAPID-конфигурация Web Push.

Ключи VAPID читаются из окружения и объявляются в статусе узла. Сами подписки
Web Push живут в таблице `push_subscriptions` и обслуживаются
`app/push/web_push.py` — второй, процесс-локальной реализации подписок здесь
больше нет (срез 7 миграции, 2026-08-21).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VapidConfig:
    """VAPID (Voluntary Application Server Identification) keys for Web Push."""

    public_key: str = ""
    private_key: str = ""
    subject: str = ""
    enabled: bool = False

    def load(self) -> None:
        self.public_key = os.environ.get("VAPID_PUBLIC_KEY", "")
        self.private_key = os.environ.get("VAPID_PRIVATE_KEY", "")
        self.subject = os.environ.get("VAPID_SUBJECT", "mailto:admin@vortex.local")
        self.enabled = bool(self.public_key and self.private_key)
        if self.enabled:
            logger.info("📱 VAPID keys loaded — Web Push enabled")
        else:
            logger.info("📱 VAPID keys not set — Web Push disabled (WS/SSE only)")


vapid = VapidConfig()
