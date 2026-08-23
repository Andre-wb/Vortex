"""
app/peer/peer_models.py — PeerInfo view, PeerRegistry facade, registry singleton, _main_loop
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

from app.config import Config
from app.peer import peer_registry_backend as _peers

logger = logging.getLogger(__name__)


# PeerInfo


@dataclass(frozen=True)
class PeerInfo:
    name: str
    ip: str
    port: int
    node_pubkey_hex: Optional[str]
    age_sec: float
    online: bool
    encrypted: bool
    shortened_pubkey: Optional[str]

    @classmethod
    def told(cls, told: dict[str, Any]) -> PeerInfo:
        return cls(
            name=told["name"],
            ip=told["ip"],
            port=told["port"],
            node_pubkey_hex=told["pubkey"],
            age_sec=told["age_sec"],
            online=told["online"],
            encrypted=told["encrypted"],
            shortened_pubkey=told["shortened_pubkey"],
        )

    def alive(self) -> bool:
        return self.online

    def has_encryption(self) -> bool:
        return self.encrypted

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "age_sec": self.age_sec,
            "online": self.online,
            "encrypted": self.encrypted,
            "pubkey": self.shortened_pubkey,
        }

    @property
    def base_url(self) -> str:
        scheme = "https" if getattr(Config, "SSL_ENABLED", False) else "http"
        return f"{scheme}://{self.ip}:{self.port}"


# PeerRegistry


class PeerRegistry:
    """Фасад над общим реестром узлов. Состояния не держит."""

    @property
    def own_ip(self) -> str:
        return _peers.own_address() or "127.0.0.1"

    @own_ip.setter
    def own_ip(self, address: str) -> None:
        _peers.set_own_address(address)

    def update(self, ip: str, name: str, port: int, node_pubkey_hex: Optional[str] = None) -> bool:
        try:
            return _peers.heard(ip, name, port, node_pubkey_hex)
        except ValueError as refusal:
            logger.warning("PeerRegistry.update: %s — узел пропущен", refusal)
            return False

    def active(self) -> list[PeerInfo]:
        return [PeerInfo.told(told) for told in _peers.alive()]

    def get(self, ip: str) -> Optional[PeerInfo]:
        try:
            told = _peers.find(ip)
        except ValueError:
            return None
        return PeerInfo.told(told) if told else None

    def cleanup(self) -> None:
        _peers.forget_dead()

    def set_peer_rooms(self, ip: str, rooms: list) -> None:
        try:
            _peers.set_rooms(ip, json.dumps(rooms))
        except ValueError as refusal:
            logger.warning("PeerRegistry.set_peer_rooms: %s — перечень пропущен", refusal)

    def get_all_peer_rooms(self) -> list[dict]:
        result = []
        for ip, name, port, document in _peers.rooms_of_the_living():
            try:
                rooms = json.loads(document)
            except json.JSONDecodeError:
                continue
            for room in rooms:
                result.append({**room, "peer_ip": ip, "peer_name": name, "peer_port": port})
        return result


registry = PeerRegistry()

_main_loop: Optional[asyncio.AbstractEventLoop] = None
