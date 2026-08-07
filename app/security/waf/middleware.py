"""WAFMiddleware — ASGI-адаптер поверх стража из крейта `vortex_waf`.

Порядок проверок, список исключённых путей, предел размера тела и сами ответы
403/413/429 живут в Rust (`WafGuard`). Здесь остаётся только работа с
ASGI-протоколом: прочитать тело, отдать готовый ответ, воспроизвести тело для
приложения.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

from app.utilites.background import spawn

logger = logging.getLogger(__name__)

_MAINTENANCE_INTERVAL_SECONDS = 300
_BODY_READ_TIMEOUT_SECONDS = 30


def _declared_length(headers) -> int | None:
    for name, value in headers:
        if name.lower() != b"content-length":
            continue
        try:
            length = int(value)
        except (TypeError, ValueError):
            return None
        if length < 0:
            return None
        return min(length, sys.maxsize)
    return None


class WAFMiddleware:
    def __init__(self, app, waf_engine):
        self.app = app
        self.waf = waf_engine
        self.guard = waf_engine.guard()
        self._cleanup_started = False

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if not self._cleanup_started:
            spawn(self._cleanup_loop())
            self._cleanup_started = True

        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        headers = scope.get("headers", [])

        plan = self.guard.plan(method, path, _declared_length(headers))
        if plan.skip:
            await self.app(scope, receive, send)
            return
        rejection = plan.response
        if rejection is not None:
            await self._respond(send, rejection, method, path)
            return

        body, received = b"", 0
        if plan.read_body:
            body, received = await self._read_body(receive, plan.body_limit, path)

        client = scope.get("client")
        response = self.guard.evaluate(
            method,
            path,
            scope.get("query_string", b""),
            headers,
            client[0] if client else None,
            received,
            body,
        )
        if response is not None:
            await self._respond(send, response, method, path)
            return

        await self.app(scope, self._replaying(receive, body), send)

    async def _read_body(self, receive, limit: int, path: str) -> tuple[bytes, int]:
        chunks: list[bytes] = []
        received = 0
        more_body = True
        while more_body:
            try:
                message = await asyncio.wait_for(receive(), timeout=_BODY_READ_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                logger.warning(f"Body read timeout for {path}")
                break
            message_type = message.get("type", "")
            if message_type != "http.request":
                break
            chunk = message.get("body", b"")
            received += len(chunk)
            if received <= limit:
                chunks.append(chunk)
            more_body = message.get("more_body", False)
        return b"".join(chunks), received

    @staticmethod
    def _replaying(receive, body: bytes):
        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return replay_receive

    async def _respond(self, send, response, method: str, path: str):
        await send(
            {
                "type": "http.response.start",
                "status": response.status,
                "headers": response.headers,
            }
        )
        await send({"type": "http.response.body", "body": response.body})
        self._log(response, method, path)

    @staticmethod
    def _log(response, method: str, path: str):
        if response.status != 403:
            logger.warning(f"WAF answered {response.status} to {method} {path}")
            return
        try:
            report = json.loads(response.body)
        except ValueError:
            report = {}
        violations = [item.get("rule_id") for item in report.get("violations", [])]
        logger.warning(f"WAF blocked {method} {path} from {report.get('client_ip')} — {violations}")

    async def _cleanup_loop(self):
        while True:
            try:
                self.waf.run_maintenance()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
            await asyncio.sleep(_MAINTENANCE_INTERVAL_SECONDS)
