"""
app/transport/stealth_http.py — HTTP-клиент с имитацией браузерного TLS fingerprint.

Проблема: Python httpx имеет характерный JA3 fingerprint, отличающийся от браузера.
ТСПУ/DPI детектирует "это Python-скрипт, не браузер" по TLS Client Hello.

Решение: curl_cffi — библиотека на базе curl-impersonate, которая полностью
имитирует TLS fingerprint Chrome/Firefox/Safari включая:
  - Cipher suites (порядок и набор)
  - TLS extensions (порядок и параметры)
  - ALPN (Application-Layer Protocol Negotiation)
  - Signature algorithms
  - Elliptic curves и point formats

JA3 fingerprint становится ИДЕНТИЧЕН настоящему Chrome 120.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Пробуем curl_cffi (полная имитация Chrome TLS), fallback на httpx
try:
    from curl_cffi.requests import AsyncSession
    _HAS_CURL_CFFI = True
    logger.info("curl_cffi загружен — TLS fingerprint = Chrome 120")
except ImportError:
    _HAS_CURL_CFFI = False
    logger.warning("curl_cffi не найден — используем httpx (JA3 fingerprint = Python)")
    logger.warning("   pip install curl_cffi для имитации браузерного TLS")


class StealthClient:
    """
    HTTP-клиент с TLS fingerprint Chrome 120.

    Использование:
        async with StealthClient() as client:
            resp = await client.get("https://example.com")
            data = resp.json()
    """

    def __init__(self, timeout: float = 10.0, verify: bool = False):
        self.timeout = timeout
        self.verify = verify
        self._session = None
        self._httpx_client = None

    async def __aenter__(self):
        if _HAS_CURL_CFFI:
            self._session = AsyncSession(
                impersonate="chrome120",  # Полная имитация Chrome 120
                timeout=self.timeout,
                verify=self.verify,
            )
        else:
            import httpx
            self._httpx_client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify,
            )
        return self

    async def __aexit__(self, *args):
        if self._session:
            # curl_cffi AsyncSession doesn't need explicit close
            self._session = None
        if self._httpx_client:
            await self._httpx_client.aclose()
            self._httpx_client = None

    async def get(self, url: str, **kwargs) -> 'StealthResponse':
        if self._session:
            resp = await self._session.get(url, **kwargs)
            return StealthResponse(resp.status_code, resp.content, resp.headers)
        else:
            resp = await self._httpx_client.get(url, **kwargs)
            return StealthResponse(resp.status_code, resp.content, dict(resp.headers))

    async def post(self, url: str, json: Any = None, **kwargs) -> 'StealthResponse':
        if self._session:
            resp = await self._session.post(url, json=json, **kwargs)
            return StealthResponse(resp.status_code, resp.content, resp.headers)
        else:
            resp = await self._httpx_client.post(url, json=json, **kwargs)
            return StealthResponse(resp.status_code, resp.content, dict(resp.headers))


class StealthResponse:
    """Unified response object for both curl_cffi and httpx."""

    def __init__(self, status_code: int, content: bytes, headers: dict):
        self.status_code = status_code
        self.content = content
        self.headers = headers

    def json(self):
        import json as _json
        return _json.loads(self.content)

    @property
    def text(self):
        return self.content.decode("utf-8", errors="replace")
