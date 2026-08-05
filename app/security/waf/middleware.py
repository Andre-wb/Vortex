"""WAFMiddleware — ASGI middleware для перехвата и анализа запросов."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import parse_qs

from app.security.waf.backend import resolve_client_ip

logger = logging.getLogger(__name__)


# Explicit trusted-proxy allowlist. By default we trust NO upstream proxy
# and use the real TCP peer — so X-Forwarded-For / X-Real-IP can no longer be
# spoofed to bypass per-IP rate limits. Operators behind a real reverse proxy set
# TRUSTED_PROXY_IPS to a comma-separated list of proxy IPs or CIDR networks
# (e.g. "10.0.0.5,192.168.1.0/24").
def _load_trusted_proxies() -> List[str]:
    raw = os.getenv("TRUSTED_PROXY_IPS", "").strip()
    return [token.strip() for token in raw.split(",") if token.strip()]


_TRUSTED_PROXIES = _load_trusted_proxies()

# Hard cap on request body size enforced at the ASGI layer, BEFORE the
# whole body is buffered into RAM for WAF analysis. Reject oversized uploads with
# 413 instead of accumulating gigabytes of chunks. Configurable via env.
_MAX_WAF_BODY_BYTES = int(os.getenv("WAF_MAX_BODY_BYTES", str(25 * 1024 * 1024)))

# Как часто чистить просроченные блокировки и историю обращений.
_MAINTENANCE_INTERVAL_SECONDS = 300


class WAFMiddleware:
    EXCLUDED_PATHS = {
        '/static/', '/health', '/favicon.ico', '/robots.txt',
        '/waf/stats', '/waf/captcha', '/waf/test',
        '/api/files/upload-chunk/',
        '/api/files/upload-init',
        '/api/files/upload-complete/',
        '/api/files/upload-cancel/',
        '/api/files/upload-status/',
        # /api/link-preview is deliberately absent: the WAF per-IP cap and
        # request analysis apply to this outbound-fetch (SSRF) surface. It is a
        # small GET with no streamed body, so buffering for inspection is safe.
        '/api/authentication/qr-',
        '/api/bmp/',              # BMP has its own rate limiting (600/min per IP)
        '/api/push-proxy/',       # Anonymous push proxy
        '/api/authentication/passkey/',
    }

    def __init__(self, app, waf_engine):
        self.app = app
        self.waf = waf_engine
        self._cleanup_started = False

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        if not self._cleanup_started:
            asyncio.create_task(self._cleanup_loop())
            self._cleanup_started = True

        method = scope.get('method', 'GET')
        _body_chunks = []

        # reject oversized bodies via Content-Length BEFORE buffering.
        _excluded_path = self._is_excluded(scope.get('path', '/'))
        if method in ('POST', 'PUT', 'PATCH') and not _excluded_path:
            _hdrs = {k.decode('latin-1').lower(): v for k, v in scope.get('headers', [])}
            cl_raw = _hdrs.get('content-length')
            if cl_raw is not None:
                try:
                    if int(cl_raw.decode('latin-1')) > _MAX_WAF_BODY_BYTES:
                        await self._send_too_large(send)
                        return
                except (ValueError, AttributeError):
                    pass

        # File-upload endpoints stream large bodies on purpose and are excluded
        # from WAF body inspection; don't buffer them into RAM at all.
        if method in ('POST', 'PUT', 'PATCH') and not _excluded_path:
            more_body = True
            _accumulated = 0
            _too_large = False
            while more_body:
                try:
                    message = await asyncio.wait_for(receive(), timeout=30)
                except asyncio.TimeoutError:
                    logger.warning(f"Body read timeout for {scope.get('path', '/')}")
                    break
                msg_type = message.get('type', '')
                if msg_type == 'http.request':
                    chunk = message.get('body', b'')
                    _accumulated += len(chunk)
                    # cap accumulated chunks even when Content-Length lied
                    # or was absent (chunked transfer-encoding).
                    if _accumulated > _MAX_WAF_BODY_BYTES:
                        _too_large = True
                        more_body = message.get('more_body', False)
                        continue
                    _body_chunks.append(chunk)
                    more_body = message.get('more_body', False)
                elif msg_type == 'http.disconnect':
                    break
                else:
                    break
            if _too_large:
                await self._send_too_large(send)
                return

        body_bytes = b''.join(_body_chunks)

        _body_sent = False

        async def replay_receive():
            nonlocal _body_sent
            if not _body_sent:
                _body_sent = True
                return {'type': 'http.request', 'body': body_bytes, 'more_body': False}
            return await receive()

        if _excluded_path:
            # excluded (streaming-upload) paths were not buffered above,
            # so pass the original receive straight through — replaying an empty
            # body here would corrupt the upload.
            await self.app(scope, receive, send)
            return

        request = self._build_request_from_scope(scope, body_bytes)

        analysis = self.waf.analyze_request(request)
        if analysis['block']:
            await self._send_blocked(send, analysis, request)
            return

        if 'x-captcha-id' in request['headers'] and 'x-captcha-answer' in request['headers']:
            cid = request['headers']['x-captcha-id']
            ans = request['headers']['x-captcha-answer']
            if not self.waf.verify_captcha(cid, ans):
                await self._send_captcha_required(send)
                return

        await self.app(scope, replay_receive, send)

    def _build_request_from_scope(self, scope, body_bytes: bytes) -> Dict:
        headers = {
            k.decode('latin-1').lower(): v.decode('latin-1')
            for k, v in scope.get('headers', [])
        }
        path = scope.get('path', '/')
        qs = scope.get('query_string', b'').decode()
        url = path + ('?' + qs if qs else '')
        return {
            'client_ip': self._get_client_ip(scope, headers),
            'method': scope.get('method', 'GET'),
            'path': path,
            'url': url,
            'headers': headers,
            'params': parse_qs(qs),
            'content_type': headers.get('content-type', ''),
            'body': body_bytes.decode('utf-8', errors='ignore') if body_bytes else '',
        }

    def _get_client_ip(self, scope, headers: Dict[str, str]) -> str:
        client = scope.get('client')
        peer = client[0] if client else None
        # Forwarding headers are honoured only for peers inside the operator's
        # TRUSTED_PROXY_IPS allowlist; the default allowlist is empty.
        return resolve_client_ip(peer, list(headers.items()), _TRUSTED_PROXIES)

    def _is_excluded(self, path: str) -> bool:
        path_lower = path.lower()
        return any(path_lower.startswith(ex.lower()) for ex in self.EXCLUDED_PATHS)

    async def _send_blocked(self, send, analysis: Dict, req: Dict):
        findings = analysis.get('findings', [])
        critical = [f for f in findings if f.get('severity') in ('high', 'critical')][:3]
        body = json.dumps({
            'error': 'Request blocked by WAF',
            'request_id': secrets.token_hex(8),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'client_ip': req.get('client_ip'),
            'violations': [
                {
                    'rule_id': f['rule_id'],
                    'description': f.get('description'),
                    'severity': f['severity'],
                }
                for f in critical
            ],
        }, ensure_ascii=False).encode()
        await send({
            'type': 'http.response.start', 'status': 403,
            'headers': [(b'content-type', b'application/json'), (b'x-waf-blocked', b'true')],
        })
        await send({'type': 'http.response.body', 'body': body})
        logger.warning(
            f"WAF blocked {req['method']} {req['path']} from {req['client_ip']} "
            f"— {[f['rule_id'] for f in critical]}"
        )

    async def _send_too_large(self, send):
        # reject oversized request bodies before they are buffered in RAM.
        body = json.dumps({
            'error': 'Request entity too large',
            'max_bytes': _MAX_WAF_BODY_BYTES,
        }).encode()
        await send({
            'type': 'http.response.start', 'status': 413,
            'headers': [(b'content-type', b'application/json'), (b'connection', b'close')],
        })
        await send({'type': 'http.response.body', 'body': body})

    async def _send_captcha_required(self, send):
        body = json.dumps({
            'error': 'CAPTCHA verification required',
            'message': 'Please solve the CAPTCHA to continue',
            'retry_after': 30,
        }).encode()
        await send({
            'type': 'http.response.start', 'status': 429,
            'headers': [
                (b'content-type', b'application/json'),
                (b'x-waf-captcha-required', b'true'),
            ],
        })
        await send({'type': 'http.response.body', 'body': body})

    async def _cleanup_loop(self):
        while True:
            try:
                self.waf.run_maintenance()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
            await asyncio.sleep(_MAINTENANCE_INTERVAL_SECONDS)
