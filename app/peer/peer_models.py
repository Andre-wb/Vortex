"""
app/peer/peer_models.py — PeerInfo dataclass, PeerRegistry class, registry singleton, _main_loop
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from app.config import Config

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# PeerInfo
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PeerInfo:
    name:            str
    ip:              str
    port:            int
    node_pubkey_hex: Optional[str] = None
    last_seen:       float         = field(default_factory=time.monotonic)

    def alive(self) -> bool:
        return (time.monotonic() - self.last_seen) < Config.PEER_TIMEOUT_SEC

    def has_encryption(self) -> bool:
        return bool(self.node_pubkey_hex and len(self.node_pubkey_hex) == 64)

    def to_dict(self) -> dict:
        return {
            "name":      self.name,
            "ip":        self.ip,
            "port":      self.port,
            "age_sec":   round(time.monotonic() - self.last_seen, 1),
            "online":    self.alive(),
            "encrypted": self.has_encryption(),
            "pubkey":    self.node_pubkey_hex[:16] + "..." if self.node_pubkey_hex else None,
        }

    @property
    def base_url(self) -> str:
        scheme = "https" if getattr(Config, "SSL_ENABLED", False) else "http"
        return f"{scheme}://{self.ip}:{self.port}"


# ══════════════════════════════════════════════════════════════════════════════
# PeerRegistry
# ══════════════════════════════════════════════════════════════════════════════

class PeerRegistry:
    def __init__(self):
        self._peers:      dict[str, PeerInfo] = {}
        self._lock        = threading.Lock()
        self.own_ip:  str = "127.0.0.1"
        self._peer_rooms: dict[str, list] = {}
        self._rooms_lock  = threading.Lock()

    def update(self, ip: str, name: str, port: int,
               node_pubkey_hex: Optional[str] = None) -> bool:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("PeerRegistry.update: invalid IP %r — ignored", ip)
            return False
        if not (1 <= port <= 65535):
            logger.warning("PeerRegistry.update: invalid port %d — ignored", port)
            return False
        with self._lock:
            is_new = ip not in self._peers
            if not is_new:
                p = self._peers[ip]
                p.name      = name
                p.port      = port
                p.last_seen = time.monotonic()
                if node_pubkey_hex and len(node_pubkey_hex) == 64:
                    p.node_pubkey_hex = node_pubkey_hex
            else:
                self._peers[ip] = PeerInfo(
                    name            = name,
                    ip              = ip,
                    port            = port,
                    node_pubkey_hex = node_pubkey_hex,
                )
                logger.info(f"🔍 New peer: {name}@{ip}:{port} encrypted={bool(node_pubkey_hex)}")
            return is_new

    def active(self) -> list[PeerInfo]:
        with self._lock:
            return [p for p in self._peers.values() if p.alive()]

    def get(self, ip: str) -> Optional[PeerInfo]:
        with self._lock:
            return self._peers.get(ip)

    def cleanup(self) -> None:
        with self._lock:
            dead = [ip for ip, p in self._peers.items() if not p.alive()]
            for ip in dead:
                del self._peers[ip]
            with self._rooms_lock:
                for ip in dead:
                    self._peer_rooms.pop(ip, None)

    def set_peer_rooms(self, ip: str, rooms: list) -> None:
        with self._rooms_lock:
            self._peer_rooms[ip] = rooms

    def get_all_peer_rooms(self) -> list[dict]:
        result     = []
        active_ips = {p.ip for p in self.active()}
        with self._rooms_lock:
            for ip, rooms in self._peer_rooms.items():
                if ip not in active_ips:
                    continue
                peer      = self.get(ip)
                peer_name = peer.name if peer else ip
                peer_port = peer.port if peer else getattr(Config, "PORT", 8000)
                for room in rooms:
                    result.append({
                        **room,
                        "peer_ip":   ip,
                        "peer_name": peer_name,
                        "peer_port": peer_port,
                    })
        return result


registry = PeerRegistry()

_main_loop: Optional[asyncio.AbstractEventLoop] = None
