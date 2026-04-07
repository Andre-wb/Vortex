"""
app/transport/global_transport.py — Глобальный P2P транспорт (gossip-протокол).

Обеспечивает децентрализованное обнаружение пиров через интернет без центрального сервера.
Каждые 30 секунд узел обменивается списком пиров с 3 случайными узлами → формируется mesh-сеть.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from app.config import Config
from app.transport.cdn_relay import cdn_config
from app.transport.stealth_http import StealthClient

logger = logging.getLogger(__name__)


def _valid_pubkey_hex(s: str) -> bool:
    """True only if s is a 64-char hex string (valid 32-byte X25519 public key)."""
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


# Таймауты gossip-протокола
_GOSSIP_INTERVAL = 30       # секунд между раундами gossip
_HEALTH_INTERVAL = 30       # секунд между проверками здоровья
_DEAD_PEER_TIMEOUT = 90     # секунд до удаления мёртвого пира
_PEER_REQUEST_TIMEOUT = 8.0 # таймаут HTTP-запросов к пирам


# ══════════════════════════════════════════════════════════════════════════════
# GlobalPeerInfo
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class GlobalPeerInfo:
    """Информация о глобальном пире."""
    ip: str
    port: int
    node_pubkey_hex: str = ""
    last_seen: float = field(default_factory=time.time)
    rooms: list[dict] = field(default_factory=list)
    version: str = ""

    def alive(self) -> bool:
        return (time.time() - self.last_seen) < _DEAD_PEER_TIMEOUT

    @property
    def addr(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def base_url(self) -> str:
        return f"https://{self.ip}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "node_pubkey_hex": self.node_pubkey_hex,
            "last_seen": self.last_seen,
            "rooms": self.rooms,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> GlobalPeerInfo:
        return cls(
            ip=d.get("ip", ""),
            port=int(d.get("port", 9000)),
            node_pubkey_hex=d.get("node_pubkey_hex", ""),
            last_seen=d.get("last_seen", time.time()),
            rooms=d.get("rooms", []),
            version=d.get("version", ""),
        )


# ══════════════════════════════════════════════════════════════════════════════
# GlobalTransport
# ══════════════════════════════════════════════════════════════════════════════

class GlobalTransport:
    """
    Глобальный транспорт: gossip-протокол для обнаружения пиров через интернет.

    - Bootstrap: подключение к начальному пиру, получение его списка пиров
    - Gossip: каждые 30 сек обмен списком пиров с 3 случайными узлами
    - Health: пинг пиров каждые 30 сек, удаление мёртвых через 90 сек
    - Персистентность: сохранение пиров в global_peers.json
    """

    def __init__(self) -> None:
        self._peers: dict[str, GlobalPeerInfo] = {}
        self._peers_file = Path("global_peers.json")
        self._running = False
        self._own_pubkey_hex: str = ""

    # ── CDN-aware URL ────────────────────────────────────────────────────

    def _get_peer_url(self, peer: GlobalPeerInfo, path: str) -> str:
        """Формирует URL для запроса к пиру, через CDN если включён."""
        if cdn_config.enabled:
            base = cdn_config.get_active_url()
            return f"{base}{path}"
        # Пробуем HTTPS, fallback на HTTP в _connect_peer / _exchange_peers
        return f"https://{peer.ip}:{peer.port}{path}"

    def _get_peer_urls(self, peer: GlobalPeerInfo, path: str) -> list[str]:
        """Формирует список URL (HTTPS + HTTP fallback) для запроса к пиру."""
        if cdn_config.enabled:
            base = cdn_config.get_active_url()
            return [f"{base}{path}"]
        return [
            f"https://{peer.ip}:{peer.port}{path}",
            f"http://{peer.ip}:{peer.port}{path}",
        ]

    # ── Жизненный цикл ────────────────────────────────────────────────────

    async def start(self, bootstrap_peers: list[str]) -> None:
        """Запуск gossip-протокола и подключение к bootstrap-пирам."""
        # Загружаем наш публичный ключ
        try:
            from app.security.crypto import load_or_create_node_keypair
            _, pub = load_or_create_node_keypair(Config.KEYS_DIR)
            self._own_pubkey_hex = pub.hex() if isinstance(pub, bytes) else bytes(pub).hex()
        except Exception as e:
            logger.warning(f"Не удалось загрузить X25519 ключ для global transport: {e}")

        # Загружаем сохранённых пиров
        self._load_peers()
        logger.info(f"🌐 Global transport: загружено {len(self._peers)} сохранённых пиров")

        # Подключаемся к bootstrap-пирам
        for addr in bootstrap_peers:
            addr = addr.strip()
            if addr:
                try:
                    await self._connect_peer(addr)
                except Exception as e:
                    logger.warning(f"Bootstrap peer {addr} недоступен: {e}")

        self._running = True
        asyncio.create_task(self._gossip_loop())
        asyncio.create_task(self._health_loop())
        logger.info(
            f"🌐 Global transport запущен: {len(self._peers)} пиров, "
            f"bootstrap={len(bootstrap_peers)}"
        )

    async def stop(self) -> None:
        """Остановка gossip-протокола."""
        self._running = False
        self._save_peers()
        logger.info("🌐 Global transport остановлен")

    # ── Gossip loop ───────────────────────────────────────────────────────

    async def _gossip_loop(self) -> None:
        """Обмен списком пиров с 3 случайными узлами (рандомизированный интервал)."""
        from app.transport.obfuscation import TrafficObfuscator
        while self._running:
            await asyncio.sleep(TrafficObfuscator.randomize_interval(_GOSSIP_INTERVAL, 0.7))
            try:
                peers = [p for p in self._peers.values() if p.alive()]
                if not peers:
                    continue
                random.shuffle(peers)
                # Обмен с 3 случайными пирами
                tasks = [self._exchange_peers(p) for p in peers[:3]]
                await asyncio.gather(*tasks, return_exceptions=True)
                self._save_peers()
            except Exception as e:
                logger.debug(f"Gossip loop error: {e}")

    async def _exchange_peers(self, peer: GlobalPeerInfo) -> None:
        """Отправляем свой список пиров, получаем чужой, мержим."""
        our_peers = [
            {"ip": p.ip, "port": p.port, "node_pubkey_hex": p.node_pubkey_hex}
            for p in self._peers.values() if p.alive()
        ]

        payload = {
            "sender_ip": _get_external_ip(),
            "sender_port": Config.PORT,
            "sender_pubkey": self._own_pubkey_hex,
            "peers": our_peers,
            "rooms": await self._get_our_public_rooms(),
        }

        url = self._get_peer_url(peer, "/api/global/gossip")
        try:
            async with StealthClient(
                timeout=_PEER_REQUEST_TIMEOUT
            ) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    cdn_config.report_success()
                    data = resp.json()
                    # Обновляем информацию о самом пире
                    peer.last_seen = time.time()
                    peer.rooms = data.get("rooms", [])[:1000]
                    # Мержим полученных пиров (cap to prevent memory abuse)
                    for rp in data.get("peers", [])[:500]:
                        self._merge_peer(rp)
        except Exception as e:
            if cdn_config.enabled:
                cdn_config.report_failure()
            logger.debug(f"Gossip exchange с {peer.addr} failed: {e}")

    # ── Health loop ───────────────────────────────────────────────────────

    async def _health_loop(self) -> None:
        """Пинг пиров, удаление мёртвых через 90 сек (рандомизированный интервал)."""
        from app.transport.obfuscation import TrafficObfuscator
        while self._running:
            await asyncio.sleep(TrafficObfuscator.randomize_interval(_HEALTH_INTERVAL, 0.7))
            try:
                dead_addrs: list[str] = []
                alive_peers = list(self._peers.values())

                # Пингуем всех пиров параллельно
                tasks = [self._ping_peer(p) for p in alive_peers]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for peer, ok in zip(alive_peers, results):
                    if ok is True:
                        peer.last_seen = time.time()
                    elif not peer.alive():
                        dead_addrs.append(peer.addr)

                # Удаляем мёртвых
                for addr in dead_addrs:
                    self._peers.pop(addr, None)
                    logger.info(f"🌐 Пир {addr} удалён (таймаут {_DEAD_PEER_TIMEOUT}с)")

                if dead_addrs:
                    self._save_peers()

            except Exception as e:
                logger.debug(f"Health loop error: {e}")

    async def _ping_peer(self, peer: GlobalPeerInfo) -> bool:
        """Пинг пира: GET /api/global/node-info (с CDN failover)."""
        url = self._get_peer_url(peer, "/api/global/node-info")
        try:
            async with StealthClient(timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    cdn_config.report_success()
                    return True
                return False
        except Exception:
            if cdn_config.enabled:
                cdn_config.report_failure()
            return False

    # ── Подключение к пиру ────────────────────────────────────────────────

    async def _connect_peer(self, addr: str) -> None:
        """Подключение к пиру по ip:port, получение его информации и списка пиров (с CDN failover)."""
        if ":" not in addr:
            addr = f"{addr}:9000"
        ip, port_str = addr.rsplit(":", 1)
        port = int(port_str)

        # Если CDN включён — строим URL через CDN, иначе пробуем HTTPS/HTTP напрямую
        if cdn_config.enabled:
            schemes_urls = [(cdn_config.get_active_url(), True)]
        else:
            schemes_urls = [(f"https://{ip}:{port}", False), (f"http://{ip}:{port}", False)]

        for base_url, is_cdn in schemes_urls:
            try:
                async with StealthClient(
                    timeout=_PEER_REQUEST_TIMEOUT
                ) as client:
                    # Запрос bootstrap
                    payload = {
                        "sender_ip": _get_external_ip(),
                        "sender_port": Config.PORT,
                        "sender_pubkey": self._own_pubkey_hex,
                    }
                    resp = await client.post(
                        f"{base_url}/api/global/bootstrap",
                        json=payload,
                    )
                    if resp.status_code == 200:
                        if is_cdn:
                            cdn_config.report_success()
                        data = resp.json()

                        # Добавляем сам bootstrap-пир
                        peer_key = f"{ip}:{port}"
                        self._peers[peer_key] = GlobalPeerInfo(
                            ip=ip,
                            port=port,
                            node_pubkey_hex=data.get("node_pubkey", ""),
                            last_seen=time.time(),
                            rooms=data.get("rooms", []),
                            version=data.get("version", ""),
                        )

                        # Мержим пиров от bootstrap-узла
                        for rp in data.get("peers", []):
                            self._merge_peer(rp)

                        logger.info(
                            f"🌐 Bootstrap: подключён к {peer_key}, "
                            f"получено {len(data.get('peers', []))} пиров"
                        )
                        return
            except Exception as e:
                if is_cdn:
                    cdn_config.report_failure()
                logger.debug(f"Bootstrap {base_url} failed: {e}")

        logger.warning(f"🌐 Не удалось подключиться к bootstrap-пиру {addr}")

    # ── Мерж пиров ────────────────────────────────────────────────────────

    def _merge_peer(self, peer_data: dict) -> None:
        """Добавляем пира из gossip-данных, если он новый."""
        ip = peer_data.get("ip", "")
        if not ip:
            return
        # Validate IP format
        try:
            import ipaddress as _ip
            _ip.ip_address(ip)
        except ValueError:
            logger.debug("_merge_peer: invalid IP %r — skipped", ip)
            return
        try:
            port = int(peer_data.get("port", 9000))
        except (TypeError, ValueError):
            return
        if not (1 <= port <= 65535):
            return

        peer_key = f"{ip}:{port}"

        # Не добавляем самого себя
        own_ip = _get_external_ip()
        if ip == own_ip and port == Config.PORT:
            return
        if ip in ("127.0.0.1", "0.0.0.0") or ip == own_ip:
            return

        new_pubkey = peer_data.get("node_pubkey_hex", "")
        if not _valid_pubkey_hex(new_pubkey):
            new_pubkey = ""

        if peer_key not in self._peers:
            self._peers[peer_key] = GlobalPeerInfo(
                ip=ip,
                port=port,
                node_pubkey_hex=new_pubkey,
                last_seen=time.time(),
            )
            logger.info(f"🌐 Новый пир из gossip: {peer_key}")
        else:
            # TOFU: pubkey устанавливается только один раз (Trust On First Use)
            existing = self._peers[peer_key]
            if new_pubkey and not existing.node_pubkey_hex:
                existing.node_pubkey_hex = new_pubkey

    # ── Поиск комнат ──────────────────────────────────────────────────────

    async def search_rooms(self, query: str) -> list[dict]:
        """Поиск публичных комнат по всем известным пирам."""
        results: list[dict] = []
        alive_peers = [p for p in self._peers.values() if p.alive()]

        async def _search_one(peer: GlobalPeerInfo) -> list[dict]:
            url = self._get_peer_url(peer, "/api/global/search-rooms")
            try:
                async with StealthClient(
                    timeout=_PEER_REQUEST_TIMEOUT
                ) as client:
                    resp = await client.get(url, params={"q": query})
                    if resp.status_code == 200:
                        cdn_config.report_success()
                        rooms = resp.json().get("rooms", [])
                        # Добавляем информацию о пире
                        for room in rooms:
                            room["peer_ip"] = peer.ip
                            room["peer_port"] = peer.port
                        return rooms
            except Exception as e:
                if cdn_config.enabled:
                    cdn_config.report_failure()
                logger.debug(f"Room search на {peer.addr} failed: {e}")
            return []

        tasks = [_search_one(p) for p in alive_peers]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in all_results:
            if isinstance(r, list):
                results.extend(r)

        return results

    # ── Добавление пира вручную (из QR-кода) ──────────────────────────────

    async def add_bootstrap_peer(self, ip: str, port: int) -> bool:
        """Вручную добавить пира (из QR-кода или ввода). Возвращает True при успехе."""
        addr = f"{ip}:{port}"
        try:
            await self._connect_peer(addr)
            return addr in self._peers
        except Exception as e:
            logger.warning(f"Не удалось добавить пира {addr}: {e}")
            return False

    # ── Получение наших публичных комнат ──────────────────────────────────

    async def _get_our_public_rooms(self) -> list[dict]:
        """Возвращает список публичных комнат этого узла."""
        try:
            from app.database import SessionLocal
            from app.models_rooms import Room
            db = SessionLocal()
            try:
                rooms = db.query(Room).filter(Room.is_private == False).all()
                return [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description or "",
                        "invite_code": r.invite_code,
                        "member_count": r.member_count() if callable(getattr(r, "member_count", None)) else 0,
                    }
                    for r in rooms
                ]
            finally:
                db.close()
        except Exception as e:
            logger.debug(f"Ошибка получения публичных комнат: {e}")
            return []

    # ── Персистентность ───────────────────────────────────────────────────

    def _load_peers(self) -> None:
        """Загрузка пиров из JSON-файла."""
        if not self._peers_file.exists():
            return
        try:
            data = json.loads(self._peers_file.read_text(encoding="utf-8"))
            for entry in data:
                peer = GlobalPeerInfo.from_dict(entry)
                if peer.ip:
                    self._peers[peer.addr] = peer
        except Exception as e:
            logger.warning(f"Ошибка загрузки global_peers.json: {e}")

    def _save_peers(self) -> None:
        """Сохранение пиров в JSON-файл."""
        try:
            data = [p.to_dict() for p in self._peers.values()]
            self._peers_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            try:
                os.chmod(self._peers_file, 0o600)
            except OSError:
                pass
        except Exception as e:
            logger.warning(f"Ошибка сохранения global_peers.json: {e}")

    # ── Публичный API ─────────────────────────────────────────────────────

    def get_peers(self) -> list[GlobalPeerInfo]:
        """Все живые пиры."""
        return [p for p in self._peers.values() if p.alive()]

    def get_all_peers(self) -> list[GlobalPeerInfo]:
        """Все пиры (включая мёртвых)."""
        return list(self._peers.values())

    def get_peer(self, addr: str) -> Optional[GlobalPeerInfo]:
        """Получить пира по адресу ip:port."""
        return self._peers.get(addr)

    def peer_count(self) -> int:
        """Количество живых пиров."""
        return len([p for p in self._peers.values() if p.alive()])

    def handle_gossip(self, sender_ip: str, sender_port: int,
                      sender_pubkey: str, peers: list[dict],
                      rooms: list[dict]) -> dict:
        """
        Обработка входящего gossip-запроса.
        Возвращает наш список пиров и комнат.
        """
        # Cap incoming lists to prevent memory exhaustion
        MAX_GOSSIP_PEERS = 500
        MAX_GOSSIP_ROOMS = 1000
        peers = peers[:MAX_GOSSIP_PEERS]
        rooms = rooms[:MAX_GOSSIP_ROOMS]

        # Обновляем / добавляем отправителя
        sender_key = f"{sender_ip}:{sender_port}"
        validated_pubkey = sender_pubkey if _valid_pubkey_hex(sender_pubkey) else ""
        if sender_key in self._peers:
            self._peers[sender_key].last_seen = time.time()
            self._peers[sender_key].rooms = rooms
            # TOFU: не перезаписываем уже известный ключ
            if validated_pubkey and not self._peers[sender_key].node_pubkey_hex:
                self._peers[sender_key].node_pubkey_hex = validated_pubkey
        else:
            self._peers[sender_key] = GlobalPeerInfo(
                ip=sender_ip,
                port=sender_port,
                node_pubkey_hex=validated_pubkey,
                last_seen=time.time(),
                rooms=rooms,
            )
            logger.info(f"🌐 Новый пир из gossip: {sender_key}")

        # Мержим пиров от отправителя
        for rp in peers:
            self._merge_peer(rp)

        self._save_peers()

        # Возвращаем наш список
        our_peers = [
            {"ip": p.ip, "port": p.port, "node_pubkey_hex": p.node_pubkey_hex}
            for p in self._peers.values() if p.alive()
        ]
        return {
            "peers": our_peers,
            "node_pubkey": self._own_pubkey_hex,
        }

    def handle_bootstrap(self, sender_ip: str, sender_port: int,
                         sender_pubkey: str) -> dict:
        """
        Обработка bootstrap-запроса от нового пира.
        Возвращает информацию об узле + список пиров.
        """
        # Добавляем отправителя
        sender_key = f"{sender_ip}:{sender_port}"
        validated_pubkey = sender_pubkey if _valid_pubkey_hex(sender_pubkey) else ""
        existing = self._peers.get(sender_key)
        self._peers[sender_key] = GlobalPeerInfo(
            ip=sender_ip,
            port=sender_port,
            # TOFU: сохраняем уже известный ключ если пир переподключается
            node_pubkey_hex=existing.node_pubkey_hex if existing and existing.node_pubkey_hex else validated_pubkey,
            last_seen=time.time(),
        )
        self._save_peers()
        logger.info(f"🌐 Bootstrap-запрос от {sender_key}")

        our_peers = [
            {"ip": p.ip, "port": p.port, "node_pubkey_hex": p.node_pubkey_hex}
            for p in self._peers.values() if p.alive()
        ]
        return {
            "node_pubkey": self._own_pubkey_hex,
            "version": "3.0.0",
            "peers": our_peers,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Singleton + helpers
# ══════════════════════════════════════════════════════════════════════════════

global_transport = GlobalTransport()


def _get_external_ip() -> str:
    """Получить внешний IP (или локальный если не определён)."""
    import socket
    for target in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect((target, 80))
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                return ip
        except Exception:
            pass
    return "127.0.0.1"
