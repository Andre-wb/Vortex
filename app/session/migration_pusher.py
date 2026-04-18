"""Background task that proactively pushes migration hints over WebSocket
when this node is under sustained overload.

Rules:
    - Check node load every ``CHECK_INTERVAL_SEC``.
    - If load stays above ``MIGRATION_SUGGEST_THRESHOLD`` for longer than
      ``SUSTAINED_SEC`` → push ``{"type":"migrate_suggest", ...}`` to every
      connected user exactly once. A cooldown (``COOLDOWN_SEC``) prevents
      flooding users if we flap just above/below the threshold.
    - Payload includes **only verified alternatives** so clients never
      receive a suggestion they can't safely use.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SEC = 10
SUSTAINED_SEC = 30
COOLDOWN_SEC = 120


class MigrationPusher:
    """Singleton-style background task managing the suggestion push cycle."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._over_since: Optional[float] = None
        self._last_push: float = 0.0

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=CHECK_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                pass
            try:
                await self._tick()
            except Exception as e:
                logger.debug("MigrationPusher tick error: %s", e)

    async def _tick(self) -> None:
        # Import lazily so the pusher can be instantiated without circular imports
        from app.session.migration import _load, _collect_alternatives, _require_signing_key
        from app.peer.connection_manager import manager as _mgr

        if not _load.should_suggest_migration():
            self._over_since = None
            return

        now = time.time()
        if self._over_since is None:
            self._over_since = now
            return
        if now - self._over_since < SUSTAINED_SEC:
            return
        if now - self._last_push < COOLDOWN_SEC:
            return

        # Sustained overload detected — build suggestion payload
        try:
            self_pubkey = _require_signing_key().pubkey_hex()
        except Exception:
            self_pubkey = ""

        alternatives = await _collect_alternatives(self_pubkey)
        if not alternatives:
            logger.info("MigrationPusher: overload but no verified alternatives yet")
            return

        payload = {
            "type": "migrate_suggest",
            "reason": "overload",
            "load": _load.snapshot()["load"],
            "targets": [a.model_dump() for a in alternatives[:5]],
        }

        sent = await _broadcast_all_rooms(_mgr, payload)
        self._last_push = now
        logger.info(
            "MigrationPusher: pushed migrate_suggest to %d WS clients (load=%.2f)",
            sent, payload["load"],
        )


async def _broadcast_all_rooms(mgr, payload: dict) -> int:
    """Send ``payload`` to every WS in every room. Returns delivery count."""
    sent = 0
    rooms = getattr(mgr, "_rooms", None) or getattr(mgr, "rooms", {}) or {}
    for room_id, users in list(rooms.items()):
        for user_id in list(users.keys()):
            try:
                ok = await mgr.send_to_user(int(room_id), int(user_id), dict(payload))
                if ok:
                    sent += 1
            except Exception:
                pass
    return sent


# Singleton instance — started/stopped from app lifespan
pusher = MigrationPusher()
