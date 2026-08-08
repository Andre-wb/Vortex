"""
Pluggable Transports — custom obfuscation, domain fronting, Shadowsocks-like.

Wraps real HTTP/WebSocket traffic in protocols indistinguishable from:
  - Random TLS noise (VortexObfuscation — custom, NOT the official obfs4proxy)
  - Normal HTTPS to CDN (domain fronting via Cloudflare/Fastly/Azure)
  - AES-256-GCM SOCKS5 proxy (Shadowsocks-like)

⚠️  VortexObfuscationTransport is a CUSTOM implementation inspired by obfs4
    concepts (random padding, AEAD framing, counter nonce).  It is NOT the
    official obfs4 / obfs4proxy by Yawning Angel.  For full obfs4 compatibility
    (PT 2.0, bridge lines, etc.) integrate obfs4proxy:
      https://gitlab.com/yawning/obfs4

Domain fronting and Shadowsocks-like transports are production-ready.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
from typing import Optional

from app.transport.obfuscation_backend import ObfuscationFrames
from app.transport.shadowsocks_backend import Shadowsocks

logger = logging.getLogger(__name__)


class VortexObfuscationTransport:
    """
    Custom obfuscation layer that makes traffic look like random encrypted noise.

    ⚠️  This is NOT obfs4proxy / obfs4-go.  It does not implement the obfs4 PT 2.0
    specification and is NOT interoperable with standard obfs4 bridges.
    It provides application-layer obfuscation only.

    Формат v2 живёт в крейте `vortex-transport` (`vortex_obfs`), здесь только шим.
    Сеанс начинается с 16-байтового пролога инициатора; каждый кадр —
    замаскированная длина и AES-256-GCM поверх `[2B data_len][data][padding]`.
    Пустой секрет означает ненастроенный транспорт: он не собирает и не
    принимает ничего.
    """

    def __init__(self, shared_secret: bytes | None = None):
        self._frames = ObfuscationFrames(shared_secret or b"")

    @property
    def is_configured(self) -> bool:
        return self._frames.is_configured

    @property
    def prologue_len(self) -> int:
        return self._frames.prologue_len

    def begin(self):
        """Сеанс инициатора. `session.prologue` уходит на провод первым."""
        return self._frames.begin()

    def accept(self, prologue: bytes):
        """Сеанс отвечающего по прологу, прочитанному из потока."""
        return self._frames.accept(prologue)

    def get_status(self) -> dict:
        return self._frames.status()


# Backward-compatible alias — older code and tests import `Obfs4Transport`
Obfs4Transport = VortexObfuscationTransport


# Meek / Domain Fronting: hide real destination behind CDN


class DomainFrontingTransport:
    """
    Domain fronting: TLS SNI points to CDN (e.g. cloudflare.com),
    but HTTP Host header points to real server.

    DPI sees: TLS connection to cloudflare.com (legit CDN)
    Reality:  HTTP request goes to vortex-relay.workers.dev

    Blocking this = blocking entire Cloudflare.
    """

    # CDN domains that support domain fronting
    FRONTABLE_DOMAINS = [
        # Cloudflare
        {"front": "www.cloudflare.com", "host": None},  # Set at runtime
        # Fastly
        {"front": "www.fastly.com", "host": None},
        # Azure CDN
        {"front": "azureedge.net", "host": None},
    ]

    def __init__(self, real_host: str, front_domain: str | None = None):
        """
        Args:
            real_host: Actual backend (e.g. "vortex-relay.workers.dev")
            front_domain: CDN domain for SNI (e.g. "www.cloudflare.com")
        """
        self.real_host = real_host
        self.front_domain = front_domain or self.FRONTABLE_DOMAINS[0]["front"]

    async def send(self, path: str, data: bytes, method: str = "POST") -> Optional[bytes]:
        """Send request via domain fronting."""
        try:
            from app.transport.stealth_http import StealthClient

            url = f"https://{self.front_domain}{path}"

            async with StealthClient() as client:
                if method == "POST":
                    resp = await client.post(
                        url,
                        content=data,
                        headers={
                            "Host": self.real_host,
                            "Content-Type": "application/octet-stream",
                            "X-Forwarded-Host": self.real_host,
                        },
                    )
                else:
                    resp = await client.get(
                        url,
                        headers={"Host": self.real_host},
                    )

                return resp.content if resp.status_code == 200 else None

        except Exception as e:
            logger.warning("Domain fronting failed (%s → %s): %s", self.front_domain, self.real_host, e)
            return None

    def get_config(self) -> dict:
        """Return config for client-side domain fronting."""
        return {
            "front_domain": self.front_domain,
            "real_host": self.real_host,
            "method": "domain_fronting",
        }


# Shadowsocks-like: SOCKS5 proxy with AEAD encryption


class ShadowsocksTransport:
    """
    Shadowsocks-подобный транспорт: прокси с AEAD-шифрованием.

    Формат v2 живёт в крейте `vortex-transport` (`shadowsocks`), здесь только шим.
    Сеанс начинается с 32-байтового пролога клиента (соль расписания); первый кадр
    несёт назначение с паддингом, дальше идут кадры данных. Каждый кадр —
    `AES-256-GCM(длина тела) ‖ AES-256-GCM(тело)`, длина на проводе заверена и
    скрыта, счётчик записи входит в nonce. Пустой пароль означает ненастроенный
    транспорт: он не собирает и не принимает ничего.

    Совместимости с настоящим Shadowsocks (SIP004/SIP022) нет и не было — вывод
    ключа и кадр другие.
    """

    def __init__(self, password: str, previous_password: str = ""):
        self._proxy = Shadowsocks(password, previous_password)

    @property
    def is_configured(self) -> bool:
        return self._proxy.is_configured

    @property
    def prologue_len(self) -> int:
        return self._proxy.prologue_len

    def reload_secrets(self, password: str, previous_password: str = "") -> None:
        """Ротация пароля: прежний остаётся принимаемым, новым запечатывается."""
        self._proxy.reload(password, previous_password)

    def add_password(self, password: str) -> bool:
        """Добавить принимаемый пароль сверх текущего и предыдущего."""
        return self._proxy.add_password(password)

    def connect(self, target_host: str, target_port: int, data: bytes = b""):
        """Сеанс клиента. `session.stream` уходит на провод первым."""
        return self._proxy.connect(target_host, target_port, data)

    def accept(self, stream: bytes) -> tuple[str, object | None]:
        """Разбор потока клиента. Возвращает (исход, сеанс | None) за один разбор."""
        return self._proxy.accept(stream)

    def generate_client_config(self, server_host: str, server_port: int) -> dict:
        """Клиентский конфиг для подключения через Shadowsocks."""
        return self._proxy.client_config(server_host, server_port)

    def get_status(self) -> dict:
        return self._proxy.status()


# TLS-in-TLS: WebSocket inside raw TLS without WS Upgrade header


class TLSInTLSTransport:
    """
    Wraps WebSocket-like bidirectional communication in plain HTTPS POST/GET.
    No WebSocket Upgrade header — DPI cannot distinguish from normal browsing.

    Protocol:
      Client → Server: POST /api/tunnel/send  {session_id, data_b64}
      Server → Client: GET  /api/tunnel/recv   {session_id} → SSE stream

    Looks like: user browsing a website with AJAX requests.
    """

    _MAX_SESSIONS = 10_000  # cap to prevent memory DoS
    _SESSION_TTL = 3600  # seconds — sessions older than this are evicted

    def __init__(self):
        self.sessions: dict[str, asyncio.Queue] = {}
        self._created_at: dict[str, float] = {}

    def create_session(self) -> str:
        """Create a new tunnel session, evicting stale ones if the cap is reached."""
        now = time.time()
        # Evict expired sessions first
        expired = [sid for sid, ts in self._created_at.items() if now - ts > self._SESSION_TTL]
        for sid in expired:
            self.sessions.pop(sid, None)
            self._created_at.pop(sid, None)

        # Hard cap: evict oldest session if still over limit
        if len(self.sessions) >= self._MAX_SESSIONS:
            oldest = min(self._created_at, key=self._created_at.__getitem__)
            self.sessions.pop(oldest, None)
            self._created_at.pop(oldest, None)

        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = asyncio.Queue(maxsize=1000)
        self._created_at[session_id] = now
        return session_id

    def close_session(self, session_id: str) -> None:
        """Close tunnel session."""
        self.sessions.pop(session_id, None)
        self._created_at.pop(session_id, None)

    async def send_to_session(self, session_id: str, data: bytes) -> bool:
        """Push data to session queue (server → client direction)."""
        q = self.sessions.get(session_id)
        if not q:
            return False
        try:
            q.put_nowait(data)
            return True
        except asyncio.QueueFull:
            return False

    async def recv_from_session(self, session_id: str, timeout: float = 30.0) -> Optional[bytes]:
        """Get data from session queue (client reads)."""
        q = self.sessions.get(session_id)
        if not q:
            return None
        try:
            return await asyncio.wait_for(q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


# Global tunnel instance
tunnel = TLSInTLSTransport()


# Bridge Nodes: volunteer relays in uncensored countries


class BridgeRegistry:
    """
    Registry of bridge nodes — volunteer relays in uncensored countries.

    Bridge nodes:
      - Accept connections from censored users
      - Forward traffic to the Vortex mesh network
      - Not listed in public peer directory (private, distributed by hand/QR)

    Similar to Tor Bridges — users share bridge addresses privately.
    """

    def __init__(self):
        self._bridges: dict[str, dict] = {}  # bridge_id → {ip, port, pubkey, added, last_seen}
        self._is_bridge = False  # Whether THIS node is a bridge

    def register_bridge(self, ip: str, port: int, pubkey_hex: str) -> str:
        """Register a new bridge. Returns bridge_id."""
        bridge_id = hashlib.sha256(f"{ip}:{port}:{pubkey_hex}".encode()).hexdigest()[:16]
        self._bridges[bridge_id] = {
            "ip": ip,
            "port": port,
            "pubkey_hex": pubkey_hex,
            "added": time.time(),
            "last_seen": time.time(),
            "success_count": 0,
            "fail_count": 0,
        }
        logger.info("Bridge registered: %s (%s:%d)", bridge_id, ip, port)
        return bridge_id

    def get_bridge(self, bridge_id: str) -> Optional[dict]:
        """Get bridge info by ID."""
        return self._bridges.get(bridge_id)

    def list_bridges(self) -> list[dict]:
        """List all known bridges."""
        return [{"id": bid, **info} for bid, info in self._bridges.items()]

    def remove_bridge(self, bridge_id: str) -> bool:
        """Remove a bridge."""
        return self._bridges.pop(bridge_id, None) is not None

    def enable_bridge_mode(self) -> None:
        """Enable this node as a bridge relay."""
        self._is_bridge = True
        logger.info("Bridge mode ENABLED — this node will relay for censored users")

    def is_bridge_mode(self) -> bool:
        """Check if this node is running as a bridge."""
        return self._is_bridge

    def report_success(self, bridge_id: str) -> None:
        """Report successful connection through bridge."""
        b = self._bridges.get(bridge_id)
        if b:
            b["last_seen"] = time.time()
            b["success_count"] += 1

    def report_failure(self, bridge_id: str) -> None:
        """Report failed connection through bridge."""
        b = self._bridges.get(bridge_id)
        if b:
            b["fail_count"] += 1

    def get_best_bridge(self) -> Optional[dict]:
        """Get the most reliable bridge (highest success rate)."""
        if not self._bridges:
            return None
        alive = [(bid, info) for bid, info in self._bridges.items() if time.time() - info["last_seen"] < 3600]
        if not alive:
            return None
        alive.sort(key=lambda x: x[1]["success_count"], reverse=True)
        bid, info = alive[0]
        return {"id": bid, **info}

    def generate_bridge_line(self, ip: str, port: int, pubkey_hex: str) -> str:
        """Generate shareable bridge line (like Tor bridge lines).

        Format: bridge <ip>:<port> <pubkey_hex_short>
        Users paste this into settings to connect through the bridge.
        """
        return f"bridge {ip}:{port} {pubkey_hex[:32]}"

    def parse_bridge_line(self, line: str) -> Optional[dict]:
        """Parse a bridge line into connection info."""
        try:
            parts = line.strip().split()
            if parts[0] != "bridge" or len(parts) < 3:
                return None
            addr = parts[1].split(":")
            return {
                "ip": addr[0],
                "port": int(addr[1]),
                "pubkey_prefix": parts[2],
            }
        except (IndexError, ValueError):
            return None


# Global instances
bridge_registry = BridgeRegistry()


# PT 2.0 Subprocess Launcher — real obfs4proxy / snowflake / meek support


class PTSubprocessTransport:
    """
    Pluggable Transport 2.0 client: launches an external PT binary
    (obfs4proxy, lyrebird, snowflake-client, meek-client) and exposes the
    resulting SOCKS5 proxy for traffic routing.

    Follows the Tor PT specification (https://spec.torproject.org/pt-spec/).

    The PT binary is managed via the standard PT env-var protocol::

        TOR_PT_MANAGED_TRANSPORT_VER  = "1"
        TOR_PT_CLIENT_TRANSPORTS     = "obfs4"
        TOR_PT_STATE_LOCATION        = <writable dir>

    Binary writes to stdout::

        VERSION 1
        CMETHOD obfs4 socks5 127.0.0.1:<PORT>
        CMETHODS DONE

    Vortex routes traffic through the SOCKS5 proxy at that port.

    Supported binaries (install any):
      - obfs4proxy / lyrebird  →  obfs4, ScrambleSuit
      - snowflake-client       →  snowflake (WebRTC, very hard to block)
      - meek-client            →  meek (domain-fronted HTTPS)
      - webtunnel-client       →  webtunnel (HTTPS upgrade)
    """

    _SEARCH_PATHS = (
        "obfs4proxy",
        "lyrebird",
        "/usr/bin/obfs4proxy",
        "/usr/local/bin/obfs4proxy",
        "/usr/bin/lyrebird",
        "/usr/local/bin/lyrebird",
    )

    def __init__(self, binary: Optional[str] = None):
        self._binary = binary
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._socks_host: Optional[str] = None
        self._socks_port: Optional[int] = None
        self._state_dir: Optional[str] = None

    @property
    def socks_addr(self) -> Optional[tuple[str, int]]:
        """SOCKS5 address exposed by the running PT, or None."""
        if self._socks_host and self._socks_port:
            return (self._socks_host, self._socks_port)
        return None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @classmethod
    def find_binary(cls, name: Optional[str] = None) -> Optional[str]:
        """Find a PT binary on $PATH or known locations."""
        import shutil

        if name:
            found = shutil.which(name)
            if found:
                return found
        for candidate in cls._SEARCH_PATHS:
            found = shutil.which(candidate)
            if found:
                return found
        return None

    async def start(self, transport: str = "obfs4", *, timeout: float = 15.0) -> bool:
        """Launch PT binary and wait for SOCKS5 endpoint. Returns True on success."""
        binary = self._binary or self.find_binary()
        if not binary:
            logger.warning("PT binary not found (install obfs4proxy / lyrebird)")
            return False

        import tempfile

        self._state_dir = tempfile.mkdtemp(prefix="vortex_pt_")

        env = {
            **os.environ,
            "TOR_PT_MANAGED_TRANSPORT_VER": "1",
            "TOR_PT_CLIENT_TRANSPORTS": transport,
            "TOR_PT_STATE_LOCATION": self._state_dir,
        }

        try:
            self._proc = await asyncio.create_subprocess_exec(
                binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (FileNotFoundError, PermissionError) as exc:
            logger.warning("PT binary %s: %s", binary, exc)
            return False

        try:
            started = await asyncio.wait_for(
                self._read_pt_startup(transport),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("PT startup timed out after %.0fs", timeout)
            await self.stop()
            return False

        if started:
            logger.info(
                "PT %s started: socks5://%s:%d (binary=%s)",
                transport,
                self._socks_host,
                self._socks_port,
                binary,
            )
        return started

    async def _read_pt_startup(self, transport: str) -> bool:
        """Parse PT stdout lines until CMETHODS DONE."""
        assert self._proc and self._proc.stdout
        while True:
            raw = await self._proc.stdout.readline()
            if not raw:
                return False
            line = raw.decode("utf-8", errors="replace").strip()
            logger.debug("PT stdout: %s", line)

            if line.startswith("VERSION"):
                continue
            if line.startswith("CMETHOD-ERROR"):
                logger.error("PT: %s", line)
                return False
            if line.startswith(f"CMETHOD {transport} socks5 "):
                addr = line.split()[-1]
                host, port_s = addr.rsplit(":", 1)
                self._socks_host = host
                self._socks_port = int(port_s)
            if line == "CMETHODS DONE":
                return self._socks_port is not None

    async def stop(self) -> None:
        """Terminate the PT subprocess."""
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._proc.kill()
            logger.info("PT subprocess stopped")
        self._proc = None
        self._socks_host = None
        self._socks_port = None
        if self._state_dir:
            import shutil

            shutil.rmtree(self._state_dir, ignore_errors=True)
            self._state_dir = None


# Transport Manager: select best transport automatically


class PluggableTransportManager:
    """
    Selects the best available transport based on network conditions.

    Priority (from most stealthy to least):
      1. Real PT (obfs4proxy / snowflake via PTSubprocessTransport)
      2. Domain fronting (if CDN relay configured)
      3. Steganography (if PIL available)
      4. TLS-in-TLS tunnel (always available)
      5. Shadowsocks-like (if configured)
      6. VortexObfuscation (custom padding+HMAC, always available)
      7. Plain WebSocket with knock (fallback)
    """

    def __init__(self):
        self.obfs4 = VortexObfuscationTransport()
        self.pt_subprocess = PTSubprocessTransport()
        self.domain_fronting: Optional[DomainFrontingTransport] = None
        self.shadowsocks = ShadowsocksTransport("")

    def configure(self, config: dict) -> None:
        """Configure available transports from app config."""
        if config.get("cdn_relay_url"):
            self.domain_fronting = DomainFrontingTransport(
                real_host=config["cdn_relay_url"].split("//")[-1].split("/")[0],
            )
        self.shadowsocks = ShadowsocksTransport(config.get("shadowsocks_password") or "")
        if config.get("pt_binary"):
            self.pt_subprocess = PTSubprocessTransport(config["pt_binary"])

    def get_available_transports(self) -> list[str]:
        """List available transport methods in priority order."""
        available = ["obfs4", "tls_tunnel", "sse", "websocket"]
        if self.obfs4.is_configured:
            available.insert(1, "vortex_obfs")

        if PTSubprocessTransport.find_binary():
            available.insert(0, "pt_subprocess")
        if self.domain_fronting:
            available.insert(0, "domain_fronting")
        if self.shadowsocks.is_configured:
            available.insert(min(2, len(available)), "shadowsocks")
        try:
            from app.transport.steganography import can_use_steganography

            if can_use_steganography():
                available.insert(min(3, len(available)), "steganography")
        except ImportError:
            pass
        if bridge_registry.list_bridges():
            available.insert(0, "bridge")
        return available

    def get_status(self) -> dict:
        """Return status of all transports."""
        pt_binary = PTSubprocessTransport.find_binary()
        return {
            "available": self.get_available_transports(),
            "domain_fronting": self.domain_fronting is not None,
            "shadowsocks": self.shadowsocks.is_configured,
            "bridges": len(bridge_registry.list_bridges()),
            "bridge_mode": bridge_registry.is_bridge_mode(),
            "pt_subprocess": pt_binary is not None,
            "pt_binary": pt_binary,
            "pt_running": self.pt_subprocess.running,
            "pt_socks": self.pt_subprocess.socks_addr,
            "obfs4": True,
            "vortex_obfs": self.obfs4.is_configured,
            "tls_tunnel": True,
            "sse": True,
            "steganography": self._check_stego(),
        }

    @staticmethod
    def _check_stego() -> bool:
        try:
            from app.transport.steganography import can_use_steganography

            return can_use_steganography()
        except ImportError:
            return False


# Global manager
transport_manager = PluggableTransportManager()
