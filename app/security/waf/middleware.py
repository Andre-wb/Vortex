"""WAFMiddleware — ASGI middleware для перехвата и анализа запросов."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Dict

from app.security.waf.captcha import WAFCaptcha
from app.security.waf.engine import WAFEngine

logger = logging.getLogger(__name__)


class WAFMiddleware:
    EXCLUDED_PATHS = {
        '/static/', '/health', '/favicon.ico', '/robots.txt',
        '/waf/stats', '/waf/captcha', '/waf/test',
        '/api/files/upload-chunk/',
        '/api/files/upload-init',
        '/api/files/upload-complete/',
        '/api/files/upload-cancel/',
        '/api/files/upload-status/',
        '/api/link-preview',
        '/api/authentication/qr-',
        '/api/authentication/passkey/',
    }

    def __init__(self, app, waf_engine: WAFEngine):
        self.app = app
        self.waf = waf_engine
        self.captcha = WAFCaptcha()
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

        if method in ('POST', 'PUT', 'PATCH'):
            more_body = True
            while more_body:
                try:
                    message = await asyncio.wait_for(receive(), timeout=30)
                except asyncio.TimeoutError:
                    logger.warning(f"Body read timeout for {scope.get('path', '/')}")
                    break
                msg_type = message.get('type', '')
                if msg_type == 'http.request':
                    _body_chunks.append(message.get('body', b''))
                    more_body = message.get('more_body', False)
                elif msg_type == 'http.disconnect':
                    break
                else:
                    break

        body_bytes = b''.join(_body_chunks)

        _body_sent = False

        async def replay_receive():
            nonlocal _body_sent
            if not _body_sent:
                _body_sent = True
                return {'type': 'http.request', 'body': body_bytes, 'more_body': False}
            return await receive()

        request = self._build_request_from_scope(scope, body_bytes)

        if self._is_excluded(request['path']):
            await self.app(scope, replay_receive, send)
            return

        analysis = self.waf.analyze_request(request)
        if analysis['block']:
            await self._send_blocked(scope, send, analysis, request)
            return

        if 'x-captcha-id' in request['headers'] and 'x-captcha-answer' in request['headers']:
            cid = request['headers']['x-captcha-id']
            ans = request['headers']['x-captcha-answer']
            if not self.captcha.verify_challenge(cid, ans):
                await self._send_captcha_required(send)
                return

        await self.app(scope, replay_receive, send)

    def _build_request_from_scope(self, scope, body_bytes: bytes) -> Dict:
        from urllib.parse import parse_qs
        client_ip = self._get_client_ip(scope)
        method = scope.get('method', 'GET')
        path = scope.get('path', '/')
        headers = {
            k.decode('latin-1').lower(): v.decode('latin-1')
            for k, v in scope.get('headers', [])
        }
        qs = scope.get('query_string', b'').decode()
        url = path + ('?' + qs if qs else '')
        return {
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'url': url,
            'headers': headers,
            'params': parse_qs(qs),
            'content_type': headers.get('content-type', ''),
            'body': body_bytes.decode('utf-8', errors='ignore') if body_bytes else '',
        }

    def _get_client_ip(self, scope) -> str:
        # Real IP from TCP connection
        client = scope.get('client')
        real_ip = client[0] if client else 'unknown'

        # Only trust forwarded headers if request comes from a trusted proxy
        if real_ip in ('127.0.0.1', '::1') or self._is_trusted_proxy(real_ip):
            headers = {
                k.decode('latin-1').lower(): v.decode('latin-1')
                for k, v in scope.get('headers', [])
            }
            for h in ('x-forwarded-for', 'x-real-ip', 'cf-connecting-ip'):
                if h in headers:
                    ip = headers[h].split(',')[0].strip()
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        pass
        return real_ip

    def _is_trusted_proxy(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback or addr.is_private
        except ValueError:
            return False

    def _is_excluded(self, path: str) -> bool:
        path_lower = path.lower()
        return any(path_lower.startswith(ex.lower()) for ex in self.EXCLUDED_PATHS)

    async def _send_blocked(self, scope, send, analysis: Dict, req: Dict):
        findings = analysis.get('findings', [])
        critical = [f for f in findings if f.get('severity') in ('high', 'critical')][:3]
        body = json.dumps({
            'error': 'Request blocked by WAF',
            'request_id': secrets.token_hex(8),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'client_ip': req.get('client_ip'),
            'violations': [{'rule_id': f['rule_id'], 'description': f.get('description'), 'severity': f['severity']} for f in critical],
        }, ensure_ascii=False).encode()
        await send({
            'type': 'http.response.start', 'status': 403,
            'headers': [(b'content-type', b'application/json'), (b'x-waf-blocked', b'true')],
        })
        await send({'type': 'http.response.body', 'body': body})
        logger.warning(f"WAF blocked {req['method']} {req['path']} from {req['client_ip']} — {[f['rule_id'] for f in critical]}")

    async def _send_captcha_required(self, send):
        body = json.dumps({
            'error': 'CAPTCHA verification required',
            'message': 'Please solve the CAPTCHA to continue',
            'retry_after': 30,
        }).encode()
        await send({
            'type': 'http.response.start', 'status': 429,
            'headers': [(b'content-type', b'application/json'), (b'x-waf-captcha-required', b'true')],
        })
        await send({'type': 'http.response.body', 'body': body})

    async def _cleanup_loop(self):
        while True:
            try:
                self.waf.clear_old_blocks()
                self.captcha.cleanup_expired()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
            await asyncio.sleep(300)
