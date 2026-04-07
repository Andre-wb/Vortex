"""
app/peer/edge_cache.py — Distributed edge cache across federation peers.

Peers cache popular files/media. When a user requests a file:
  1. Check local disk → serve immediately
  2. Check nearby peers (LAN, then WAN) → fetch + cache locally
  3. Fallback to origin (uploader's node)

Cache eviction: LRU with configurable max size (default 500MB).
Cache TTL: 24 hours (configurable).
Peer query: parallel HTTP to N nearest peers, first-response wins.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from app.config import Config
from app.security.ssl_context import make_peer_ssl_context

logger = logging.getLogger(__name__)

# ── Shared pool for cache fetches ────────────────────────────────────────────
_cache_pool = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, connect=3.0),
    limits=httpx.Limits(max_keepalive_connections=10, max_connections=40),
    verify=make_peer_ssl_context(),
)

# ── Configuration ────────────────────────────────────────────────────────────

_MAX_CACHE_SIZE_MB = int(os.environ.get("EDGE_CACHE_MAX_MB", "500"))
_MAX_CACHE_SIZE    = _MAX_CACHE_SIZE_MB * 1024 * 1024
_CACHE_TTL         = float(os.environ.get("EDGE_CACHE_TTL", "86400"))  # 24h
_MAX_SINGLE_FILE   = 50 * 1024 * 1024  # don't cache files > 50MB
_FETCH_PEERS       = 3  # query up to N peers in parallel


@dataclass
class CacheEntry:
    file_hash:  str
    size:       int
    stored_at:  float = field(default_factory=time.monotonic)
    last_hit:   float = field(default_factory=time.monotonic)
    hits:       int   = 0

    def expired(self) -> bool:
        return (time.monotonic() - self.stored_at) > _CACHE_TTL


class EdgeCache:
    """
    LRU edge cache for files replicated across peers.

    Stored on disk under UPLOAD_DIR/.edge_cache/<sha256>.
    Metadata in-memory (OrderedDict for LRU).
    """

    def __init__(self):
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()
        self._total_size: int = 0
        self._lock = asyncio.Lock()
        self._cache_dir: Optional[Path] = None
        self._ready = False

    def start(self) -> None:
        self._cache_dir = Config.UPLOAD_DIR / ".edge_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._scan_existing()
        self._ready = True
        logger.info(
            f"📦 Edge cache ready: {len(self._entries)} files, "
            f"{self._total_size / 1024 / 1024:.1f}/{_MAX_CACHE_SIZE_MB}MB"
        )

    def _scan_existing(self) -> None:
        """Load existing cached files from disk."""
        if not self._cache_dir:
            return
        for f in self._cache_dir.iterdir():
            if f.is_file() and len(f.stem) == 64:  # sha256 hex
                size = f.stat().st_size
                self._entries[f.stem] = CacheEntry(
                    file_hash=f.stem, size=size,
                    stored_at=f.stat().st_mtime,
                )
                self._total_size += size

    # ── Local lookup ─────────────────────────────────────────────────────────

    def get_local(self, file_hash: str) -> Optional[Path]:
        """Return cached file path if present and not expired."""
        if not self._ready or not file_hash:
            return None
        entry = self._entries.get(file_hash)
        if not entry:
            return None
        if entry.expired():
            self._evict(file_hash)
            return None
        path = self._cache_dir / file_hash
        if not path.exists():
            self._entries.pop(file_hash, None)
            return None
        entry.hits += 1
        entry.last_hit = time.monotonic()
        self._entries.move_to_end(file_hash)
        return path

    # ── Fetch from peers ─────────────────────────────────────────────────────

    async def fetch_from_peers(
        self,
        file_hash: str,
        file_id:   int,
        peer_ips:  list[tuple[str, int]],
    ) -> Optional[Path]:
        """
        Try to fetch a file from nearby peers in parallel.
        First successful response wins; file is cached locally.
        """
        if not self._ready or not peer_ips:
            return None

        selected = peer_ips[:_FETCH_PEERS]

        async def _try_peer(ip: str, port: int) -> Optional[bytes]:
            for scheme in ("https", "http"):
                try:
                    r = await _cache_pool.get(
                        f"{scheme}://{ip}:{port}/api/files/download/{file_id}",
                        headers={"X-Edge-Cache": "1"},
                    )
                    if r.status_code == 200 and len(r.content) <= _MAX_SINGLE_FILE:
                        # Verify hash
                        h = hashlib.sha256(r.content).hexdigest()
                        if h == file_hash:
                            return r.content
                except Exception:
                    pass
            return None

        tasks = [_try_peer(ip, port) for ip, port in selected]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is not None:
                path = await self.store(file_hash, result)
                return path

        return None

    # ── Store ────────────────────────────────────────────────────────────────

    async def store(self, file_hash: str, content: bytes) -> Optional[Path]:
        """Cache file content locally. Returns path or None if too large."""
        if not self._ready or len(content) > _MAX_SINGLE_FILE:
            return None

        async with self._lock:
            # Evict until we have space
            while self._total_size + len(content) > _MAX_CACHE_SIZE and self._entries:
                self._evict_oldest()

            path = self._cache_dir / file_hash
            path.write_bytes(content)
            self._entries[file_hash] = CacheEntry(
                file_hash=file_hash, size=len(content),
            )
            self._total_size += len(content)
            self._entries.move_to_end(file_hash)

        return path

    # ── Announce to peers ────────────────────────────────────────────────────

    async def announce_file(
        self,
        file_hash: str,
        file_id:   int,
        peer_ips:  list[tuple[str, int]],
    ) -> None:
        """Inform nearby peers about a newly uploaded file for pre-caching."""
        for ip, port in peer_ips[:5]:
            try:
                await _cache_pool.post(
                    f"https://{ip}:{port}/api/edge-cache/announce",
                    json={"file_hash": file_hash, "file_id": file_id,
                          "origin_ip": Config.HOST, "origin_port": Config.PORT},
                )
            except Exception:
                pass

    # ── Eviction ─────────────────────────────────────────────────────────────

    def _evict(self, file_hash: str) -> None:
        entry = self._entries.pop(file_hash, None)
        if entry:
            self._total_size -= entry.size
            path = self._cache_dir / file_hash
            path.unlink(missing_ok=True)

    def _evict_oldest(self) -> None:
        if self._entries:
            oldest_key = next(iter(self._entries))
            self._evict(oldest_key)

    async def cleanup_expired(self) -> int:
        """Remove expired entries. Call periodically."""
        async with self._lock:
            expired = [k for k, v in self._entries.items() if v.expired()]
            for k in expired:
                self._evict(k)
            return len(expired)

    # ── Stats ────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        total_hits = sum(e.hits for e in self._entries.values())
        return {
            "files":      len(self._entries),
            "size_mb":    round(self._total_size / 1024 / 1024, 1),
            "max_mb":     _MAX_CACHE_SIZE_MB,
            "total_hits": total_hits,
            "utilization": round(self._total_size / _MAX_CACHE_SIZE * 100, 1) if _MAX_CACHE_SIZE else 0,
        }


# Global instance
edge_cache = EdgeCache()
