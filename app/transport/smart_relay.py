"""
app/transport/smart_relay.py — Geo-aware relay selection with latency probing.

Solves: "Нет глобального CDN уровня Telegram; delivery speed зависит от mesh-топологии"

Instead of random relay selection, picks the relay peer with minimum
estimated total latency (sender→relay + relay→recipient).

Features:
  1. Latency probing: periodic ICMP-free HTTP HEAD pings to known peers
  2. Region estimation: IP → rough geo-region (no external API, IP range heuristic)
  3. Relay scoring: score = latency_to_sender + estimated_latency_to_recipient
  4. Direct path preference: if direct latency < 200ms, skip relay entirely
  5. Top-K selection: pick from 3 best relays (load balancing)
  6. Cache: latency measurements cached 60s, region cached indefinitely

Architecture:
  ┌────────┐     relay A (50ms)     ┌────────┐
  │ Sender ├─────────────────────────┤ Recip. │
  │        ├──┐  relay B (120ms) ┌──┤        │
  └────────┘  └──────────────────┘  └────────┘
              relay C (80ms) ← chosen: 50ms wins
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.security.ssl_context import make_peer_ssl_context

logger = logging.getLogger(__name__)

# Shared HTTP client for latency probes (lightweight HEAD requests)
_probe_pool = httpx.AsyncClient(
    timeout=httpx.Timeout(3.0, connect=2.0),
    limits=httpx.Limits(max_keepalive_connections=10, max_connections=30),
    verify=make_peer_ssl_context(),
)

# ── Region estimation from IP (no external API) ─────────────────────────────

# Rough IP-to-region mapping for latency estimation between regions.
# Not for geolocation — only for relay scoring.
_REGION_LATENCY_MATRIX: dict[tuple[str, str], float] = {
    # Same region: ~20ms
    ("eu", "eu"): 20, ("us", "us"): 30, ("asia", "asia"): 40,
    ("ru", "ru"): 30, ("other", "other"): 50,
    # Cross-region estimates
    ("eu", "us"): 90, ("us", "eu"): 90,
    ("eu", "asia"): 150, ("asia", "eu"): 150,
    ("us", "asia"): 120, ("asia", "us"): 120,
    ("eu", "ru"): 40, ("ru", "eu"): 40,
    ("us", "ru"): 100, ("ru", "us"): 100,
    ("asia", "ru"): 80, ("ru", "asia"): 80,
}


def estimate_region(ip: str) -> str:
    """
    Rough region estimate from IP address.

    Uses first octet ranges (very approximate, but zero external dependencies).
    Only used for relay scoring, not for privacy-sensitive purposes.
    """
    if not ip or ip.startswith(("127.", "10.", "192.168.", "172.")):
        return "local"

    try:
        first = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return "other"

    # Very rough heuristic based on IANA allocation blocks
    if first in range(2, 77) or first in range(128, 170):
        return "us"
    elif first in range(77, 96) or first in range(176, 195):
        return "eu"
    elif first in range(96, 128) or first in range(200, 224):
        return "asia"
    elif first in range(170, 176) or first in range(195, 200):
        return "ru"
    return "other"


def _inter_region_latency(region_a: str, region_b: str) -> float:
    """Estimated latency between two regions in ms."""
    if region_a == region_b:
        return _REGION_LATENCY_MATRIX.get((region_a, region_b), 30)
    key = (region_a, region_b)
    return _REGION_LATENCY_MATRIX.get(key, _REGION_LATENCY_MATRIX.get((region_b, region_a), 100))


# ── Peer latency data ────────────────────────────────────────────────────────

@dataclass
class PeerLatency:
    """Measured latency data for a peer."""
    ip: str
    port: int
    region: str = ""
    latency_ms: float = 999.0       # Last measured RTT
    last_probe: float = 0.0          # time.monotonic() of last probe
    probe_failures: int = 0
    online: bool = True


class SmartRelayRouter:
    """
    Selects optimal relay peers based on latency measurements.

    Usage:
        router = SmartRelayRouter()
        await router.start()

        # Find best relay for a message
        relay = await router.select_relay(sender_ip, recipient_ip, candidate_peers)
        if relay:
            send_via(relay.ip, relay.port)
        else:
            send_direct()
    """

    PROBE_INTERVAL = 60.0     # seconds between probes
    PROBE_TIMEOUT = 3.0       # seconds
    CACHE_TTL = 60.0          # latency cache TTL
    DIRECT_THRESHOLD = 200.0  # ms — if direct path faster, skip relay
    TOP_K = 3                 # pick from top-K relays (load balance)

    def __init__(self):
        self._peers: dict[str, PeerLatency] = {}  # "ip:port" → PeerLatency
        self._lock = asyncio.Lock()
        self._probe_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start background latency probing."""
        if self._probe_task is None:
            self._probe_task = asyncio.create_task(self._probe_loop())
            logger.info("SmartRelayRouter started")

    async def stop(self):
        """Stop background probing."""
        if self._probe_task:
            self._probe_task.cancel()
            self._probe_task = None

    def register_peer(self, ip: str, port: int):
        """Register a peer for latency probing."""
        key = f"{ip}:{port}"
        if key not in self._peers:
            self._peers[key] = PeerLatency(
                ip=ip, port=port,
                region=estimate_region(ip),
            )

    def unregister_peer(self, ip: str, port: int):
        """Remove a peer from tracking."""
        self._peers.pop(f"{ip}:{port}", None)

    async def probe_peer(self, ip: str, port: int) -> float:
        """
        Measure RTT to a peer via HTTP HEAD.

        Returns latency in ms, or 999.0 on failure.
        """
        key = f"{ip}:{port}"
        peer = self._peers.get(key)
        if not peer:
            peer = PeerLatency(ip=ip, port=port, region=estimate_region(ip))
            self._peers[key] = peer

        try:
            t0 = time.monotonic()
            r = await _probe_pool.head(
                f"https://{ip}:{port}/api/health",
                follow_redirects=False,
            )
            latency = (time.monotonic() - t0) * 1000
            peer.latency_ms = latency
            peer.last_probe = time.monotonic()
            peer.probe_failures = 0
            peer.online = True
            return latency
        except Exception:
            peer.probe_failures += 1
            if peer.probe_failures >= 5:
                peer.online = False
            return 999.0

    async def select_relay(
        self,
        sender_ip: str,
        recipient_ip: str,
        candidate_peers: list[tuple[str, int]],
    ) -> Optional[PeerLatency]:
        """
        Select the optimal relay peer for message delivery.

        Returns None if direct delivery is faster than any relay.

        Scoring: total_latency = latency(sender→relay) + latency(relay→recipient)
        The relay→recipient latency is estimated from region if not measured.
        """
        if not candidate_peers:
            return None

        sender_region = estimate_region(sender_ip)
        recipient_region = estimate_region(recipient_ip)

        # Check if direct path is likely fast enough
        direct_est = _inter_region_latency(sender_region, recipient_region)
        if direct_est < self.DIRECT_THRESHOLD:
            # Direct delivery preferred
            return None

        # Score each candidate relay
        scored: list[tuple[float, PeerLatency]] = []
        now = time.monotonic()

        for ip, port in candidate_peers:
            key = f"{ip}:{port}"
            peer = self._peers.get(key)
            if not peer:
                peer = PeerLatency(ip=ip, port=port, region=estimate_region(ip))
                self._peers[key] = peer

            if not peer.online:
                continue

            # sender→relay: use measured latency if fresh, else estimate by region
            if peer.last_probe > 0 and (now - peer.last_probe) < self.CACHE_TTL:
                leg1 = peer.latency_ms
            else:
                leg1 = _inter_region_latency(sender_region, peer.region)

            # relay→recipient: estimate by region (we can't probe recipient)
            leg2 = _inter_region_latency(peer.region, recipient_region)

            total = leg1 + leg2
            scored.append((total, peer))

        if not scored:
            return None

        # Sort by total latency, pick randomly from top-K for load balancing
        scored.sort(key=lambda x: x[0])
        top_k = scored[:self.TOP_K]

        # Weighted random selection from top-K (lower latency = higher weight)
        if len(top_k) == 1:
            return top_k[0][1]

        import random
        weights = [1.0 / (s[0] + 1) for s in top_k]
        total_w = sum(weights)
        r = random.random() * total_w
        cumulative = 0.0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return top_k[i][1]
        return top_k[0][1]

    def get_peer_latencies(self) -> list[dict]:
        """Return all peer latency measurements (for monitoring)."""
        return [
            {
                "ip": p.ip,
                "port": p.port,
                "region": p.region,
                "latency_ms": round(p.latency_ms, 1),
                "online": p.online,
                "failures": p.probe_failures,
            }
            for p in self._peers.values()
        ]

    def stats(self) -> dict:
        total = len(self._peers)
        online = sum(1 for p in self._peers.values() if p.online)
        avg_latency = 0.0
        measured = [p for p in self._peers.values() if p.last_probe > 0 and p.online]
        if measured:
            avg_latency = sum(p.latency_ms for p in measured) / len(measured)
        return {
            "total_peers": total,
            "online_peers": online,
            "avg_latency_ms": round(avg_latency, 1),
            "regions": list(set(p.region for p in self._peers.values())),
        }

    async def _probe_loop(self):
        """Background loop: probe all peers periodically."""
        while True:
            try:
                await asyncio.sleep(self.PROBE_INTERVAL)
                peers = list(self._peers.values())
                if not peers:
                    continue

                # Probe up to 20 peers concurrently
                tasks = []
                for peer in peers[:50]:
                    tasks.append(self.probe_peer(peer.ip, peer.port))

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    ok = sum(1 for r in results if isinstance(r, float) and r < 500)
                    logger.debug("Latency probes: %d/%d ok", ok, len(tasks))

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.debug("Probe loop error: %s", e)


# Global instance
smart_relay = SmartRelayRouter()
