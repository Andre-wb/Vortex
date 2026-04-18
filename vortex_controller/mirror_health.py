"""Background health checker for controller mirrors.

Periodically probes each configured mirror URL and records its status.
Exposed via ``/v1/mirrors`` (health attached to each entry) and a dedicated
``/v1/mirrors/health`` so clients can pick a live mirror without guessing.

Probe strategy:
    - Plain HTTPS mirrors → HEAD (follow redirects, 5s timeout)
    - ``ipfs://`` URIs    → HEAD via a public gateway
    - ``.onion`` URIs     → skipped unless a SOCKS5 Tor proxy is configured
                             via ``TOR_SOCKS`` env var (e.g. 127.0.0.1:9050)

The checker runs in the FastAPI lifespan; it makes no persistent state —
results live in ``app.state.mirror_health``.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SEC = 300   # 5 min between full sweeps
PROBE_TIMEOUT_SEC = 5.0


@dataclass
class MirrorStatus:
    url: str
    ok: bool = False
    last_checked: float = 0.0
    latency_ms: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "ok": self.ok,
            "last_checked": int(self.last_checked),
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


@dataclass
class HealthState:
    """In-memory health state shared via app.state."""
    by_url: dict[str, MirrorStatus] = field(default_factory=dict)
    last_sweep: float = 0.0

    def snapshot(self) -> dict:
        return {
            "last_sweep": int(self.last_sweep),
            "mirrors": [s.to_dict() for s in self.by_url.values()],
        }


class MirrorHealthChecker:
    def __init__(self, urls: list[str], tor_socks: Optional[str] = None):
        self.urls = urls
        self.tor_socks = tor_socks
        self.state = HealthState(by_url={u: MirrorStatus(url=u) for u in urls})
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        # Do an immediate sweep so /v1/mirrors has data on first request
        await self._sweep()
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
                return  # stop requested
            except asyncio.TimeoutError:
                pass
            try:
                await self._sweep()
            except Exception as e:
                logger.debug("mirror health sweep failed: %s", e)

    async def _sweep(self) -> None:
        if not self.urls:
            return
        tasks = [self._probe(u) for u in self.urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.state.last_sweep = time.time()

    async def _probe(self, url: str) -> None:
        status = self.state.by_url.setdefault(url, MirrorStatus(url=url))
        status.last_checked = time.time()

        target = _probe_url(url)
        if target is None:
            status.ok = False
            status.error = "unsupported scheme"
            status.latency_ms = None
            return

        if _is_onion(url) and not self.tor_socks:
            # Without a Tor proxy we can't reach .onion — treat as unknown.
            status.ok = False
            status.error = "no tor proxy configured"
            status.latency_ms = None
            return

        proxy = None
        if _is_onion(url) and self.tor_socks:
            proxy = f"socks5h://{self.tor_socks}"

        client_kw = dict(timeout=PROBE_TIMEOUT_SEC, follow_redirects=True)
        if proxy is not None:
            client_kw["proxy"] = proxy

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(**client_kw) as http:
                r = await http.head(target)
                # Some gateways reject HEAD — fall back to a small GET.
                if r.status_code in (405, 400):
                    r = await http.get(target)
                r.raise_for_status()
        except Exception as e:
            status.ok = False
            status.error = type(e).__name__ + ": " + str(e)[:120]
            status.latency_ms = None
            return

        status.ok = True
        status.error = None
        status.latency_ms = int((time.perf_counter() - t0) * 1000)


def _is_onion(url: str) -> bool:
    return ".onion" in url.lower()


def _probe_url(url: str) -> Optional[str]:
    """Translate a mirror URL into something HTTP-probeable."""
    low = url.lower()
    if low.startswith("ipfs://"):
        cid = url[len("ipfs://"):]
        return f"https://ipfs.io/ipfs/{cid}/"
    if low.startswith("ipns://"):
        name = url[len("ipns://"):]
        return f"https://ipfs.io/ipns/{name}/"
    if low.startswith(("http://", "https://")):
        return url
    return None


def load_tor_socks_from_env() -> Optional[str]:
    return os.getenv("TOR_SOCKS", "").strip() or None
