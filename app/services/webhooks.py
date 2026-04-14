"""
app/services/webhooks.py — Outgoing webhooks for room events.

Rooms can register webhook URLs that receive POST notifications on events:
  - message: new message in room
  - member_join / member_leave
  - file_upload
  - call_start / call_end

Payload is signed with HMAC-SHA256 (room-specific secret) in X-Vortex-Signature header.
Retries: 3 attempts with exponential backoff (1s, 4s, 16s).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Shared pool for webhook delivery ────────────────────────────────────────
_webhook_pool = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, connect=3.0),
    limits=httpx.Limits(max_keepalive_connections=5, max_connections=20),
    verify=True,
)


@dataclass
class WebhookConfig:
    """Webhook registration for a room."""
    room_id:    int
    url:        str
    secret:     str = field(default_factory=lambda: os.urandom(32).hex())
    events:     list[str] = field(default_factory=lambda: ["message"])
    active:     bool  = True
    created_at: float = field(default_factory=time.time)
    failures:   int   = 0
    last_error: str   = ""


class WebhookManager:
    """
    Manages webhook registrations and delivery.

    In-memory storage (for production: persist to DB).
    """

    def __init__(self):
        self._hooks: dict[int, list[WebhookConfig]] = {}  # room_id → list
        self._lock = asyncio.Lock()

    async def register(self, room_id: int, url: str, events: list[str] | None = None) -> WebhookConfig:
        hook = WebhookConfig(
            room_id=room_id,
            url=url,
            events=events or ["message"],
        )
        async with self._lock:
            if room_id not in self._hooks:
                self._hooks[room_id] = []
            self._hooks[room_id].append(hook)
        logger.info(f"Webhook registered for room {room_id}: {url}")
        return hook

    async def unregister(self, room_id: int, url: str) -> bool:
        async with self._lock:
            hooks = self._hooks.get(room_id, [])
            before = len(hooks)
            self._hooks[room_id] = [h for h in hooks if h.url != url]
            return len(self._hooks[room_id]) < before

    async def fire(self, room_id: int, event: str, payload: dict) -> None:
        """Fire webhooks for a room event. Non-blocking (background tasks)."""
        hooks = self._hooks.get(room_id, [])
        for hook in hooks:
            if not hook.active:
                continue
            if event not in hook.events and "*" not in hook.events:
                continue
            asyncio.create_task(self._deliver(hook, event, payload))

    async def _deliver(self, hook: WebhookConfig, event: str, payload: dict) -> None:
        """Deliver webhook with retries and HMAC signing."""
        body = json.dumps({
            "event":   event,
            "room_id": hook.room_id,
            "ts":      int(time.time()),
            "data":    payload,
        }, separators=(",", ":"), ensure_ascii=False)

        signature = hmac.new(
            hook.secret.encode(), body.encode(), hashlib.sha256
        ).hexdigest()

        headers = {
            "Content-Type":       "application/json",
            "X-Hook-Event":       event,
            "X-Hook-Signature":   f"sha256={signature}",
            "User-Agent":         "Mozilla/5.0 (compatible)",
        }

        for attempt in range(3):
            try:
                r = await _webhook_pool.post(hook.url, content=body, headers=headers)
                if r.status_code < 400:
                    hook.failures = 0
                    return
                hook.last_error = f"HTTP {r.status_code}"
            except Exception as e:
                hook.last_error = str(e)[:200]

            hook.failures += 1
            if attempt < 2:
                await asyncio.sleep(1 * (4 ** attempt))  # 1s, 4s

        # Disable after 10 consecutive failures
        if hook.failures >= 10:
            hook.active = False
            logger.warning(f"Webhook disabled (10 failures): {hook.url}")

    def get_hooks(self, room_id: int) -> list[dict]:
        return [
            {
                "url":     h.url,
                "events":  h.events,
                "active":  h.active,
                "failures": h.failures,
            }
            for h in self._hooks.get(room_id, [])
        ]

    def stats(self) -> dict:
        total = sum(len(v) for v in self._hooks.values())
        active = sum(1 for hooks in self._hooks.values() for h in hooks if h.active)
        return {"total": total, "active": active, "rooms": len(self._hooks)}


# Global instance
webhook_manager = WebhookManager()
