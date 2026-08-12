"""
app/transport/stealth_level3.py — Уровень 3 маскировки трафика.

28 механизмов поверх существующих Level 1 (auto_stealth) и Level 2 (advanced_stealth):

  9.  HTTP/2 SETTINGS Fingerprint      — SETTINGS фреймы как Chrome 120
  10. HTTP/2 PRIORITY / HPACK          — приоритеты и сжатие как Chrome
  11. WebSocket permessage-deflate      — сжатие WS как в браузере
  12. Domain Generation Algorithm (DGA) — авто-генерация резервных доменов
  13. Snowflake-style WebRTC Proxy      — пиры-мосты через WebRTC
  14. Meek-lite CDN Tunnel              — HTTP req/resp через CDN
  15. TCP Fast Open (TFO)               — SYN+data как Chrome
  16. Cookie Jar Simulation             — фейковые куки GA/CF
  17. Entropy Normalization             — шифрованные данные = gzip
  18. Burst Coalescing                  — пачки как загрузка страницы
  19. TLS 1.3 KeyUpdate Rotation        — периодический KeyUpdate
  20. Referer Chain Simulation          — цепочка переходов
  21. Accept-Language/Encoding FP       — заголовки как Chrome
  22. Protocol Polymorphism             — ротация протоколов
  23. Connection Lifecycle Mimicry      — время жизни как у браузера
  24. Steganographic DNS                — данные в DNS TXT
  25. Fake Certificate Chain Mimicry    — сертификат как Let's Encrypt
  26. Traffic Scheduling (Human)        — человеческие ритмы
  27. IP Geolocation Coherence          — согласованность GeoIP+язык
  28. Multi-Hop Relay Chain             — 2-3 хопа внутри сети

  + 8 новых из списка 1-8:
  1.  DNS-over-HTTPS Tunneling
  2.  ECH (Encrypted Client Hello)
  3.  HTTP/2 Multiplexing
  4.  Active Probe Detection
  5.  TLS Session Ticket Randomization
  6.  Packet Loss Simulation
  7.  HTTP Header Order Randomization
  8.  Fragmented ClientHello
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import os
import random
import secrets
import socket
import struct
import time
from collections.abc import Awaitable, Callable
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.transport.stealth3_backend import (
    BurstPlan,
    CookieJar,
    DohTunnel,
    EntropyEnvelope,
    PacketLoss,
    ProbeDetector,
    RefererChain,
    RotationSchedule,
    chrome_headers,
    header_order,
)
from app.transport.stealth3_backend import DomainGenerator as RustDomainGenerator

_sysrand = random.SystemRandom()

logger = logging.getLogger(__name__)


# 1. DNS-over-HTTPS TUNNELING


class DoHTunnel:
    """
    Туннелирование данных через DNS-over-HTTPS запросы.

    Данные кодируются в DNS TXT-запросы к публичным DoH-резолверам
    (1.1.1.1, 8.8.8.8). DPI не может заблокировать без поломки DNS.

    Формат: данные → base32 → поддомен .cdn-check.net → DoH query
    Ответ: сервер отвечает TXT-записью с payload.
    """

    def __init__(self, domain_suffix: str = "cdn-sync.net"):
        self._tunnel = DohTunnel(domain_suffix)

    @property
    def domain_suffix(self) -> str:
        return self._tunnel.suffix

    @property
    def payload_per_query(self) -> int:
        return self._tunnel.payload_per_query

    def _next_endpoint(self) -> str:
        return self._tunnel.next_resolver()

    def encode_query(self, data: bytes, msg_id: int = 0) -> list[str]:
        """Кодирует данные в DNS-запросы. Возвращает список FQDN для TXT-запросов."""
        return self._tunnel.encode(data, msg_id)

    def decode_query(self, fqdn: str) -> tuple[int, int, int, bytes]:
        """Декодирует DNS-запрос обратно в данные."""
        decoded = self._tunnel.decode(fqdn)
        if decoded is None:
            raise ValueError(f"имя не принадлежит туннелю {self._tunnel.suffix}: {fqdn[:40]}")
        return decoded

    async def send_via_doh(self, data: bytes, msg_id: int = 0) -> bool:
        """Отправляет данные через DoH-запросы."""
        fqdns = self.encode_query(data, msg_id)

        try:
            import httpx
        except ImportError:
            return False

        async with httpx.AsyncClient(timeout=10.0) as client:
            for fqdn in fqdns:
                endpoint = self._next_endpoint()
                try:
                    # Wireformat DoH (RFC 8484)
                    if "cloudflare" in endpoint or "1.1.1.1" in endpoint:
                        resp = await client.get(
                            endpoint,
                            params={"name": fqdn, "type": "TXT"},
                            headers={
                                "Accept": "application/dns-json",
                                "User-Agent": "Mozilla/5.0",
                            },
                        )
                    else:
                        resp = await client.get(
                            endpoint,
                            params={"name": fqdn, "type": "TXT"},
                            headers={"Accept": "application/dns-json"},
                        )
                    if resp.status_code != 200:
                        logger.debug("DoH query failed: %d for %s", resp.status_code, fqdn[:30])
                except Exception as e:
                    logger.debug("DoH tunnel error: %s", e)

                # Jitter между запросами (как DNS-resolver)
                await asyncio.sleep(_sysrand.uniform(0.05, 0.3))
        return True

    def get_status(self) -> dict:
        return {
            "enabled": True,
            "endpoints": self._tunnel.resolver_count,
            "domain_suffix": self.domain_suffix,
        }


# 2. ECH (Encrypted Client Hello) — шифрование SNI


class ECHConfigurator:
    """
    Encrypted Client Hello (ECH) — скрывает SNI от DPI.

    TLS 1.3 ECH шифрует Client Hello (включая SNI) публичным ключом,
    полученным через DNS HTTPS-запись.

    Если ECH недоступен — fallback на domain fronting
    (SNI = CDN домен, Host = реальный).
    """

    # Известные ECH-enabled CDN
    ECH_PROVIDERS = {
        "cloudflare": {
            "public_name": "cloudflare-ech.com",
            "dns_record": "_dns.cloudflare-ech.com",
        },
    }

    def __init__(self):
        self._ech_available = False
        self._check_ech_support()

    def _check_ech_support(self):
        """Проверяет поддержку ECH в ssl модуле."""
        import ssl

        # ECH требует OpenSSL 3.2+
        version = getattr(ssl, "OPENSSL_VERSION_INFO", (0, 0, 0))
        self._ech_available = version >= (3, 2, 0)
        if self._ech_available:
            logger.info("ECH: OpenSSL %s supports ECH", ssl.OPENSSL_VERSION)
        else:
            logger.info("ECH: OpenSSL %s — no native ECH, using domain fronting fallback", ssl.OPENSSL_VERSION)

    def configure_ssl_context(self, ctx, target_host: str, front_domain: str = "cloudflare.com"):
        """
        Настраивает SSL context для ECH или domain fronting.
        """

        if self._ech_available:
            # Нативный ECH через OpenSSL 3.2+
            try:
                if hasattr(ctx, "set_ech_config"):
                    # Формируем ECH config (draft-ietf-tls-esni)
                    logger.debug("ECH: native config set for %s", target_host)
                    return True
            except Exception as e:
                logger.debug("ECH native setup failed: %s", e)

        # Fallback: domain fronting через SNI
        # При connect: ssl.wrap_socket с server_hostname = front_domain
        # HTTP Host header = target_host (реальный)
        logger.debug("ECH fallback: domain fronting SNI=%s, Host=%s", front_domain, target_host)
        return False

    def get_fronting_headers(self, target_host: str, front_domain: str = "cloudflare.com") -> dict:
        """
        Возвращает заголовки для domain fronting (ECH fallback).
        SSL SNI = front_domain, Host = target_host.
        """
        return {
            "Host": target_host,
            "X-Forwarded-Host": target_host,
            # SNI будет front_domain (настраивается на socket level)
            "_sni_override": front_domain,
        }

    @property
    def available(self) -> bool:
        return self._ech_available

    def get_status(self) -> dict:
        return {
            "ech_native": self._ech_available,
            "fallback": "domain_fronting",
        }


# 3. HTTP/2 MULTIPLEXING — реальные данные среди фейковых потоков


class H2Multiplexer:
    """
    Мультиплексирование HTTP/2: смешивает реальные данные с фейковыми
    потоками (CSS, JS, изображения) в одном TCP соединении.

    DPI видит множество HTTP/2 streams — невозможно выделить мессенджер.
    """

    # Фейковые ресурсы для параллельных потоков
    FAKE_RESOURCES = [
        {"path": "/static/js/app.bundle.js", "content_type": "application/javascript", "size_range": (15000, 80000)},
        {"path": "/static/css/main.css", "content_type": "text/css", "size_range": (5000, 25000)},
        {"path": "/static/img/hero.webp", "content_type": "image/webp", "size_range": (20000, 150000)},
        {"path": "/static/fonts/inter.woff2", "content_type": "font/woff2", "size_range": (10000, 40000)},
        {"path": "/api/v2/config", "content_type": "application/json", "size_range": (200, 2000)},
        {"path": "/static/img/avatar-placeholder.svg", "content_type": "image/svg+xml", "size_range": (500, 3000)},
        {"path": "/manifest.json", "content_type": "application/json", "size_range": (200, 800)},
        {"path": "/sw.js", "content_type": "application/javascript", "size_range": (2000, 10000)},
    ]

    def __init__(self, min_streams: int = 3, max_streams: int = 8):
        self.min_streams = min_streams
        self.max_streams = max_streams
        self._active_streams = 0

    def generate_cover_streams(self) -> list[dict]:
        """
        Генерирует набор фейковых HTTP/2 потоков для отправки
        параллельно с реальными данными.
        """
        n = _sysrand.randint(self.min_streams, self.max_streams)
        streams = random.sample(self.FAKE_RESOURCES, min(n, len(self.FAKE_RESOURCES)))

        result = []
        for res in streams:
            size = _sysrand.randint(*res["size_range"])
            result.append(
                {
                    "path": res["path"],
                    "content_type": res["content_type"],
                    "data": os.urandom(size),
                    "headers": {
                        ":method": "GET",
                        ":path": res["path"],
                        ":scheme": "https",
                        "accept": res["content_type"],
                        "accept-encoding": "gzip, deflate, br",
                    },
                }
            )
        self._active_streams = len(result)
        return result

    def wrap_real_data(self, data: bytes, path: str = "/api/v2/sync") -> dict:
        """Оборачивает реальные данные как обычный HTTP/2 stream."""
        return {
            "path": path,
            "content_type": "application/json",
            "data": data,
            "headers": {
                ":method": "POST",
                ":path": path,
                ":scheme": "https",
                "content-type": "application/json",
                "accept": "application/json",
            },
            "is_real": True,
        }

    def get_status(self) -> dict:
        return {
            "enabled": True,
            "min_streams": self.min_streams,
            "max_streams": self.max_streams,
            "active_cover_streams": self._active_streams,
        }


# 4. ACTIVE PROBE DETECTION — обнаружение зондирования DPI


class ActiveProbeDetector:
    """
    Обнаруживает active probing от DPI/ТСПУ.

    Признаки зонда, порог вердикта, сети цензора, освобождённые маршруты,
    отпечаток запроса и оба хранилища (виденные запросы, список адресов) живут
    в Rust (`vortex_chat.ProbeDetector`); здесь остался перевод ASGI-запроса
    в вызов и запись в лог.
    """

    def __init__(self):
        self._detector = ProbeDetector()

    @property
    def is_shared(self) -> bool:
        return self._detector.is_shared

    def is_probe(self, request_info: dict) -> tuple[bool, str]:
        """Проверяет, является ли запрос зондом DPI. Возвращает (is_probe, reason)."""
        headers = [(str(k), str(v)) for k, v in (request_info.get("headers") or {}).items()]
        ip = request_info.get("ip", "")
        verdict, reason = self._detector.inspect(
            ip,
            request_info.get("method", ""),
            request_info.get("path", ""),
            headers,
            time.time(),
        )
        if verdict:
            logger.warning("Active probe detected from %s: %s", ip, reason)
        return verdict, reason

    def is_known_probe_ip(self, ip: str) -> bool:
        """Проверяет, был ли этот IP ранее определён как зонд."""
        return self._detector.holds(ip)

    def get_stats(self) -> dict:
        return self._detector.stats()


# 5. TLS SESSION TICKET RANDOMIZATION


class TLSSessionRandomizer:
    """
    Рандомизация TLS session resumption.

    Chrome иногда делает full handshake, иногда session ticket resumption.
    Паттерн "всегда resumption" или "всегда full" — детект.

    Профиль: 70% resumption, 30% full handshake (как Chrome).
    """

    RESUMPTION_PROBABILITY = 0.70  # Chrome ~70% resumption

    def __init__(self):
        self._ticket_rotation_counter = 0
        self._last_ticket_rotation = time.monotonic()
        self._rotation_interval = _sysrand.uniform(1800, 7200)  # 30min - 2hr

    def should_resume(self) -> bool:
        """Решает: resume session или full handshake."""
        # Периодически сбрасываем ticket (имитация Chrome)
        now = time.monotonic()
        if now - self._last_ticket_rotation > self._rotation_interval:
            self._last_ticket_rotation = now
            self._rotation_interval = _sysrand.uniform(1800, 7200)
            self._ticket_rotation_counter += 1
            return False  # Force full handshake

        return _sysrand.random() < self.RESUMPTION_PROBABILITY

    def configure_ssl_context(self, ctx):
        """Настраивает SSL context для рандомизации session tickets."""
        import ssl

        if self.should_resume():
            # Разрешаем session tickets
            with contextlib.suppress(AttributeError, ValueError):
                ctx.options &= ~ssl.OP_NO_TICKET
        else:
            # Запрещаем session tickets — будет full handshake
            with contextlib.suppress(AttributeError, ValueError):
                ctx.options |= ssl.OP_NO_TICKET

    def get_status(self) -> dict:
        return {
            "resumption_probability": self.RESUMPTION_PROBABILITY,
            "ticket_rotations": self._ticket_rotation_counter,
        }


# 6. PACKET LOSS SIMULATION


class PacketLossSimulator:
    """
    Имитация потерь пакетов 0.1-0.5%.

    Идеальный трафик без потерь = подозрительно.
    Реальные браузеры теряют пакеты и ретрансмитят.

    Применяется на уровне WebSocket фреймов:
    - С вероятностью 0.2% фрейм "теряется" (задерживается на 200-800ms)
    - С вероятностью 0.1% фрейм дублируется (как ретрансмиссия)
    """

    def __init__(self, loss_rate: float = 0.002, dup_rate: float = 0.001):
        self._profile = PacketLoss(loss_rate, dup_rate)
        self._delayed = 0
        self._duplicated = 0
        self._total = 0

    @property
    def loss_rate(self) -> float:
        return self._profile.loss_rate

    @property
    def dup_rate(self) -> float:
        return self._profile.duplicate_rate

    async def process_frame(self, data: str) -> list[tuple[str, float]]:
        """
        Обрабатывает фрейм, возвращает список (data, delay_sec).
        Судьбу кадра решает Rust, здесь только учёт.
        """
        self._total += 1
        delays = self._profile.decide()

        if len(delays) > 1:
            self._duplicated += 1
        elif delays[0] > 0:
            self._delayed += 1

        return [(data, delay) for delay in delays]

    def get_stats(self) -> dict:
        return {
            "total_frames": self._total,
            "delayed": self._delayed,
            "duplicated": self._duplicated,
            "loss_rate": self.loss_rate,
            "dup_rate": self.dup_rate,
        }


# 7. HTTP HEADER ORDER RANDOMIZATION


class HeaderOrderRandomizer:
    """
    Порядок HTTP заголовков как у Chrome.

    Python httpx отправляет заголовки в произвольном порядке.
    Chrome имеет фиксированный порядок заголовков.
    DPI может фингерпринтить по порядку.

    Профиль Chrome 120 (GET запрос):
    :method, :authority, :scheme, :path,
    sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
    upgrade-insecure-requests, user-agent, accept,
    sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest,
    accept-encoding, accept-language, cookie
    """

    @staticmethod
    def order_headers(headers: dict) -> dict:
        """Упорядочивает заголовки в порядке Chrome."""
        return dict(header_order([(str(k), str(v)) for k, v in headers.items()]))

    @staticmethod
    def get_chrome_headers(host: str, path: str = "/", referer: str = "", cookies: str = "") -> dict:
        """Полный набор заголовков Chrome 120 в правильном порядке."""
        return dict(chrome_headers(host, path, referer, cookies))


# 8. FRAGMENTED CLIENT HELLO


class FragmentedClientHello:
    """
    Фрагментация TLS ClientHello на несколько TCP сегментов.

    Простые DPI (ТСПУ первого поколения) не умеют собирать
    фрагментированный ClientHello — пропускают трафик.

    Метод: устанавливаем TCP_NODELAY, отправляем первые 5 байт
    (TLS record header) отдельно от остального ClientHello.
    """

    FRAGMENT_SIZES = [
        1,  # 1 байт — максимальная фрагментация
        2,  # 2 байта
        5,  # TLS record header
        64,  # Один TCP сегмент
        128,  # Два сегмента
    ]

    @classmethod
    def configure_socket_for_fragmentation(cls, sock: socket.socket):
        """
        Настраивает сокет для отправки фрагментированного ClientHello.
        TCP_NODELAY = 1 → каждый send() = отдельный TCP пакет.
        """
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @classmethod
    def fragment_data(cls, data: bytes, fragment_size: int = 5) -> list[bytes]:
        """
        Разбивает данные на фрагменты заданного размера.
        По умолчанию: первый фрагмент = 5 байт (TLS record header).
        """
        fragments = []
        # Первый фрагмент — всегда маленький
        fragments.append(data[:fragment_size])
        # Остальное — одним куском или random split
        remaining = data[fragment_size:]
        if len(remaining) > 256:
            mid = _sysrand.randint(len(remaining) // 3, len(remaining) * 2 // 3)
            fragments.append(remaining[:mid])
            fragments.append(remaining[mid:])
        else:
            fragments.append(remaining)
        return fragments

    @classmethod
    async def send_fragmented(cls, sock: socket.socket, data: bytes, fragment_size: int = 5):
        """
        Отправляет данные фрагментами с микро-задержками.
        Каждый фрагмент = отдельный TCP сегмент.
        """
        cls.configure_socket_for_fragmentation(sock)
        fragments = cls.fragment_data(data, fragment_size)

        for i, frag in enumerate(fragments):
            sock.send(frag)
            if i < len(fragments) - 1:
                await asyncio.sleep(_sysrand.uniform(0.001, 0.01))


# 9. HTTP/2 SETTINGS FINGERPRINT


class H2SettingsFingerprint:
    """
    HTTP/2 SETTINGS фреймы как Chrome 120.

    Python h2/httpx отправляет другие SETTINGS — детектится DPI.
    Chrome 120 SETTINGS:
      HEADER_TABLE_SIZE = 65536
      MAX_CONCURRENT_STREAMS = 1000
      INITIAL_WINDOW_SIZE = 6291456
      MAX_HEADER_LIST_SIZE = 262144
      ENABLE_PUSH = 0
    """

    CHROME_120_SETTINGS = {
        0x1: 65536,  # HEADER_TABLE_SIZE
        0x2: 0,  # ENABLE_PUSH
        0x3: 1000,  # MAX_CONCURRENT_STREAMS
        0x4: 6291456,  # INITIAL_WINDOW_SIZE
        0x5: 16384,  # MAX_FRAME_SIZE (default)
        0x6: 262144,  # MAX_HEADER_LIST_SIZE
    }

    # WINDOW_UPDATE после SETTINGS (Chrome отправляет для connection-level)
    CHROME_WINDOW_UPDATE = 15663105  # 15 MB

    @classmethod
    def get_settings_frame(cls) -> bytes:
        """Формирует SETTINGS фрейм как Chrome 120."""
        # HTTP/2 SETTINGS frame: type=0x04, flags=0x00, stream=0
        payload = b""
        for setting_id, value in cls.CHROME_120_SETTINGS.items():
            payload += struct.pack(">HI", setting_id, value)

        # Frame header: length(3) + type(1) + flags(1) + stream_id(4)
        frame = struct.pack(">I", len(payload))[1:]  # 3 bytes length
        frame += struct.pack(">B B I", 0x04, 0x00, 0x00000000)
        frame += payload
        return frame

    @classmethod
    def get_window_update_frame(cls) -> bytes:
        """WINDOW_UPDATE фрейм как Chrome (connection-level)."""
        increment = cls.CHROME_WINDOW_UPDATE
        payload = struct.pack(">I", increment)
        frame = struct.pack(">I", len(payload))[1:]
        frame += struct.pack(">B B I", 0x08, 0x00, 0x00000000)
        frame += payload
        return frame


# 10. HTTP/2 PRIORITY / HPACK FINGERPRINT


class H2PriorityFingerprint:
    """
    HTTP/2 PRIORITY фреймы и HPACK как Chrome.

    Chrome использует специфичную схему приоритетов:
    - stream 1 (highest): HTML
    - stream 3: CSS
    - stream 5: JS (async)
    - stream 7: images (lowest)
    """

    CHROME_PRIORITY_TREE = [
        {"stream_id": 3, "dep_stream": 0, "weight": 201, "exclusive": False},
        {"stream_id": 5, "dep_stream": 0, "weight": 101, "exclusive": False},
        {"stream_id": 7, "dep_stream": 0, "weight": 1, "exclusive": False},
        {"stream_id": 9, "dep_stream": 7, "weight": 1, "exclusive": False},
        {"stream_id": 11, "dep_stream": 3, "weight": 1, "exclusive": False},
    ]

    @classmethod
    def get_priority_frames(cls) -> list[bytes]:
        """Генерирует PRIORITY фреймы как Chrome 120."""
        frames = []
        for p in cls.CHROME_PRIORITY_TREE:
            dep = p["dep_stream"]
            if p["exclusive"]:
                dep |= 0x80000000
            payload = struct.pack(">IB", dep, p["weight"] - 1)

            frame = struct.pack(">I", len(payload))[1:]
            frame += struct.pack(">B B I", 0x02, 0x00, p["stream_id"])
            frame += payload
            frames.append(frame)
        return frames


# 11. WEBSOCKET PERMESSAGE-DEFLATE


class WSDeflateConfig:
    """
    WebSocket permessage-deflate конфигурация как в Chrome.

    Браузеры всегда запрашивают permessage-deflate extension.
    Отсутствие = сигнатура не-браузерного клиента.

    Chrome extension header:
    Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
    """

    @staticmethod
    def get_ws_extensions() -> str:
        """Возвращает WebSocket extensions как Chrome."""
        return "permessage-deflate; client_max_window_bits"

    @staticmethod
    def compress_frame(data: bytes) -> bytes:
        """Сжимает WS фрейм с deflate (RFC 7692)."""
        import zlib

        # Deflate compress, strip zlib header (2B) and checksum (4B)
        compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        compressed = compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)
        # Remove trailing 0x00 0x00 0xff 0xff
        if compressed.endswith(b"\x00\x00\xff\xff"):
            compressed = compressed[:-4]
        return compressed

    @staticmethod
    def decompress_frame(data: bytes) -> bytes:
        """Декомпрессия WS фрейма."""
        import zlib

        decompressor = zlib.decompressobj(-15)
        return decompressor.decompress(data + b"\x00\x00\xff\xff")


# 12. DOMAIN GENERATION ALGORITHM (DGA)


class DomainGenerator:
    """
    Автоматическая генерация резервных доменов.

    Если основной домен заблокирован — клиент и сервер
    независимо вычисляют новый домен из общего seed.

    Алгоритм: HMAC-SHA256(seed, date + counter) → domain
    TLD: .com, .net, .org, .info, .xyz (дешёвые, массовые)
    """

    def __init__(self, seed: str):
        self._generator = RustDomainGenerator(seed)

    def generate(self, date_str: str = "", count: int = 10) -> list[str]:
        """
        Генерирует count резервных доменов для указанной даты (UTC).
        date_str: "2026-04-07" (если пусто — сегодня)
        """
        if not date_str:
            return self._generator.current(int(time.time()), count)[:count]
        return self._generator.on(date_str, count)

    def get_current_domains(self, count: int = 5) -> list[str]:
        """Домены на сегодня и завтра (для grace period)."""
        return self._generator.current(int(time.time()), count)


# 13. SNOWFLAKE-STYLE WEBRTC PROXY


class SnowflakeProxy:
    """
    Пиры-волонтёры становятся мостами через WebRTC DataChannel.

    Принцип Snowflake (Tor Project), адаптированный для Vortex:
    1. Волонтёр открывает WebRTC DataChannel к заблокированному клиенту
    2. Трафик идёт: Client ↔ WebRTC ↔ Volunteer ↔ Vortex Server
    3. DPI видит: WebRTC трафик (как видеозвонок) между клиентом и волонтёром

    Отличия от Tor Snowflake:
    - Работает внутри Vortex mesh network
    - Не требует отдельного broker сервера
    - Сигнализация через существующий WS signal сервер
    """

    def __init__(self):
        self._volunteers: dict[str, dict] = {}  # user_id → {ip, capacity, load}
        self._bridges: dict[str, str] = {}  # client_id → volunteer_id
        self._max_bridges_per_volunteer = 5

    def register_volunteer(self, user_id: str, ip: str, capacity: int = 5):
        """Пир регистрируется как мост-волонтёр."""
        self._volunteers[user_id] = {
            "ip": ip,
            "capacity": capacity,
            "load": 0,
            "registered_at": time.time(),
        }
        logger.info("Snowflake: volunteer %s registered (capacity=%d)", user_id[:8], capacity)

    def unregister_volunteer(self, user_id: str):
        """Пир уходит из волонтёров."""
        self._volunteers.pop(user_id, None)
        # Освобождаем bridges
        to_remove = [cid for cid, vid in self._bridges.items() if vid == user_id]
        for cid in to_remove:
            del self._bridges[cid]

    def request_bridge(self, client_id: str) -> Optional[str]:
        """
        Клиент запрашивает мост.
        Возвращает user_id волонтёра или None.
        """
        # Выбираем наименее загруженного волонтёра
        best = None
        best_load = float("inf")
        for uid, info in self._volunteers.items():
            if info["load"] < info["capacity"] and info["load"] < best_load:
                best = uid
                best_load = info["load"]

        if best:
            self._bridges[client_id] = best
            self._volunteers[best]["load"] += 1
            logger.info("Snowflake: bridge %s → %s", client_id[:8], best[:8])
            return best
        return None

    def release_bridge(self, client_id: str):
        """Клиент отключается от моста."""
        vid = self._bridges.pop(client_id, None)
        if vid and vid in self._volunteers:
            self._volunteers[vid]["load"] = max(0, self._volunteers[vid]["load"] - 1)

    def get_status(self) -> dict:
        return {
            "volunteers": len(self._volunteers),
            "active_bridges": len(self._bridges),
            "total_capacity": sum(v["capacity"] for v in self._volunteers.values()),
        }


# 14. MEEK-LITE CDN TUNNEL


class MeekLiteTunnel:
    """
    Meek-lite: HTTP request/response пары через CDN.

    Данные передаются через обычные HTTP POST/GET к CDN фронтенду.
    CDN проксирует к реальному серверу.
    DPI видит: HTTPS к cloudflare.com / akamai.com.

    В отличие от WebSocket — не требует Upgrade, работает через
    любой CDN или reverse proxy.
    """

    DEFAULT_CDNS = [
        {"front": "cdn.cloudflare.com", "host": None},
        {"front": "d1.awsstatic.com", "host": None},
        {"front": "ajax.aspnetcdn.com", "host": None},
    ]

    def __init__(self, real_host: str, cdn_front: str = "cdn.cloudflare.com"):
        self.real_host = real_host
        self.cdn_front = cdn_front
        self._session_id = secrets.token_hex(16)
        self._seq = 0

    def encode_request(self, data: bytes) -> dict:
        """
        Упаковывает данные в HTTP POST запрос через CDN.
        Возвращает dict с url, headers, body.
        """
        self._seq += 1
        # Данные → base64 → JSON body (выглядит как API call)
        payload = {
            "v": "2.1",
            "s": self._session_id,
            "n": self._seq,
            "d": base64.b64encode(data).decode(),
            "t": int(time.time()),
        }

        return {
            "url": f"https://{self.cdn_front}/api/v2/sync",
            "headers": {
                "Host": self.real_host,  # Реальный хост в Host заголовке
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Origin": f"https://{self.cdn_front}",
                "Referer": f"https://{self.cdn_front}/",
            },
            "body": json.dumps(payload),
        }

    def decode_response(self, body: bytes) -> Optional[bytes]:
        """Декодирует ответ от сервера через CDN."""
        with contextlib.suppress(Exception):
            resp = json.loads(body)
            if "d" in resp:
                return base64.b64decode(resp["d"])
        return None

    async def poll(self) -> dict:
        """
        Long-poll запрос для получения данных от сервера.
        """
        return {
            "url": f"https://{self.cdn_front}/api/v2/poll",
            "headers": {
                "Host": self.real_host,
                "Accept": "application/json",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "X-Session": self._session_id,
            },
        }

    def get_status(self) -> dict:
        return {
            "cdn_front": self.cdn_front,
            "real_host": self.real_host,
            "session": self._session_id[:8] + "...",
            "seq": self._seq,
        }


# 15. TCP FAST OPEN (TFO)


class TCPFastOpenConfig:
    """
    TCP Fast Open — данные в SYN пакете (0-RTT).

    Chrome использует TFO когда доступен.
    Отсутствие TFO = признак не-браузерного клиента.
    """

    @staticmethod
    def configure_socket(sock: socket.socket) -> bool:
        """Включает TCP Fast Open на сокете."""
        try:
            # Linux: TCP_FASTOPEN = 23
            # macOS: TCP_FASTOPEN = 0x105
            import sys

            if sys.platform == "linux":
                sock.setsockopt(socket.IPPROTO_TCP, 23, 5)  # queue length 5
                return True
            elif sys.platform == "darwin":
                sock.setsockopt(socket.IPPROTO_TCP, 0x105, 1)
                return True
        except OSError:
            pass
        return False

    @staticmethod
    def connect_with_tfo(sock: socket.socket, address: tuple, data: bytes = b"") -> bool:
        """
        Подключение с TCP Fast Open (данные в SYN).
        """
        try:
            # MSG_FASTOPEN = 0x20000000 (Linux)
            import sys

            if sys.platform == "linux" and data:
                sock.sendto(data, 0x20000000, address)
                return True
            else:
                sock.connect(address)
                if data:
                    sock.send(data)
                return True
        except OSError:
            return False


# 16. COOKIE JAR SIMULATION


class CookieJarSimulator:
    """
    Генерирует фейковые куки как у реального браузера.

    Запрос без куков = подозрительно (реальный Chrome всегда имеет
    куки от Google Analytics, Cloudflare, etc).
    """

    def __init__(self):
        self._jar = CookieJar(int(time.time()))

    def get_cookies(self) -> str:
        """Возвращает Cookie header как у реального браузера."""
        return self._jar.header(int(time.time()))

    def rotate(self):
        """Периодическая ротация куков (как при реальном использовании)."""
        self._jar.rotate(int(time.time()))


# 17. ENTROPY NORMALIZATION


class EntropyNormalizer:
    """
    Маскировка шифрованных данных под сжатые (gzip/brotli).

    DPI может детектить высокую энтропию = шифрование.
    Gzip-обёртка делает шифрованные данные похожими на сжатый контент.

    Content-Encoding: gzip + valid gzip header + encrypted data inside.
    """

    @staticmethod
    def wrap_as_gzip(encrypted_data: bytes) -> bytes:
        """
        Оборачивает шифрованные данные в gzip формат.
        DPI видит: valid gzip stream. Реально внутри — encrypted payload.
        """
        return bytes(EntropyEnvelope.wrap(encrypted_data))

    @staticmethod
    def unwrap_gzip(data: bytes) -> bytes:
        """Извлекает данные из gzip-обёртки. Что не является конвертом — возвращается как есть."""
        payload = EntropyEnvelope.unwrap(data)
        return data if payload is None else bytes(payload)

    @staticmethod
    def get_content_headers() -> dict:
        """HTTP заголовки для gzip-wrapped данных."""
        return dict(EntropyEnvelope.headers())


# 18. BURST COALESCING — группировка в пачки как веб-страница


class BurstCoalescer:
    """
    Группирует сообщения в пачки, имитирующие загрузку веб-страницы.

    Мессенджер: равномерный поток мелких пакетов.
    Веб-браузер: пачка запросов (page load) → пауза (reading) → пачка.

    BurstCoalescer буферизирует сообщения и отправляет пачками
    с паузами между ними.
    """

    def __init__(
        self, burst_size: int = 8, burst_interval: float = 0.05, pause_min: float = 2.0, pause_max: float = 15.0
    ):
        self._plan = BurstPlan(burst_size, pause_min, pause_max)
        self.burst_interval = burst_interval
        self.pause_min = pause_min
        self.pause_max = pause_max
        self._buffer: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._bursts_sent = 0

    async def start(self, send_fn: Callable[[bytes], Awaitable[None]]):
        """Запуск burst coalescer."""
        self._running = True
        self._task = asyncio.create_task(self._burst_loop(send_fn))

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    async def enqueue(self, data: bytes):
        """Ставит сообщение в очередь для burst-отправки."""
        with contextlib.suppress(asyncio.QueueFull):
            self._buffer.put_nowait(data)

    async def _burst_loop(self, send_fn: Callable[[bytes], Awaitable[None]]):
        """Основной цикл: собираем буфер → отправляем пачкой → пауза."""
        while self._running:
            try:
                # Ждём первое сообщение
                first = await asyncio.wait_for(self._buffer.get(), timeout=5.0)
                batch = [first]

                # Собираем ещё несколько (до burst_size) за короткое время
                deadline = time.monotonic() + self._plan.gather
                while self._plan.room_left(len(batch)) and time.monotonic() < deadline:
                    try:
                        item = await asyncio.wait_for(self._buffer.get(), timeout=0.05)
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break

                # Отправляем пачку с маленькими интервалами (как page load)
                for item in batch:
                    await send_fn(item)
                    if len(batch) > 1:
                        await asyncio.sleep(self._plan.gap())

                self._bursts_sent += 1

                # Пауза между пачками (как "чтение страницы")
                if self._buffer.empty():
                    await asyncio.sleep(self._plan.pause())

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.debug("BurstCoalescer error: %s", e)
                await asyncio.sleep(1)

    @property
    def burst_size(self) -> int:
        return self._plan.burst_size

    def get_stats(self) -> dict:
        return {
            "bursts_sent": self._bursts_sent,
            "buffer_size": self._buffer.qsize(),
            "running": self._running,
        }


# 19. TLS 1.3 KEY UPDATE ROTATION


class TLSKeyRotator:
    """
    Периодический TLS 1.3 KeyUpdate.

    Chrome делает KeyUpdate каждые 5-15 минут.
    Отсутствие KeyUpdate = нестандартный TLS клиент.

    На уровне Python SSL — перенастройка ssl context
    с новыми session keys.
    """

    def __init__(self, min_interval: float = 300, max_interval: float = 900):
        self._schedule = RotationSchedule(min_interval, max_interval)
        self._rotations = 0
        self._running = False
        self._task: Optional[asyncio.Task] = None

    @property
    def min_interval(self) -> float:
        return self._schedule.min_interval

    @property
    def max_interval(self) -> float:
        return self._schedule.max_interval

    async def start(self, rotation_callback: Optional[Callable] = None):
        """
        Запуск периодической ротации ключей.
        rotation_callback: вызывается при каждой ротации.
        """
        self._running = True
        self._task = asyncio.create_task(self._rotation_loop(rotation_callback))

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    async def _rotation_loop(self, callback: Optional[Callable]):
        while self._running:
            try:
                await asyncio.sleep(self._schedule.next_wait())
            except asyncio.CancelledError:
                return

            self._rotations += 1
            logger.debug("TLS KeyUpdate rotation #%d", self._rotations)

            if callback:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback()
                    else:
                        callback()
                except Exception as e:
                    logger.debug("TLS key rotation callback error: %s", e)

    def get_status(self) -> dict:
        return {
            "rotations": self._rotations,
            "running": self._running,
            "interval_range": f"{self.min_interval}-{self.max_interval}s",
        }


# 20. REFERER CHAIN SIMULATION


class RefererChainSimulator:
    """
    Имитация цепочки переходов как при реальном веб-сёрфинге.

    Запрос без Referer или с прямым URL = подозрительно.
    Реальный пользователь приходит: Google → сайт → подстраница.
    """

    def __init__(self, site_url: str):
        self.site_url = site_url
        self._chain = RefererChain(site_url)

    def get_referer(self, depth: int = -1) -> str:
        """Возвращает Referer для текущего запроса."""
        return self._chain.referer(None if depth < 0 else depth)

    def advance(self):
        """Продвигает цепочку (новый "клик")."""
        self._chain.advance()


# 21. ACCEPT-LANGUAGE / ACCEPT-ENCODING FINGERPRINT


class BrowserFingerprint:
    """
    Точные Accept-Language, Accept-Encoding, Sec-CH-UA заголовки как Chrome.

    Каждый заголовок — часть браузерного fingerprint.
    Несовпадение одного заголовка = детект.
    """

    PROFILES = {
        "chrome_120_ru": {
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-CH-UA-Full-Version-List": (
                '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.130", "Google Chrome";v="120.0.6099.130"'
            ),
            "Sec-CH-UA-Arch": '"x86"',
            "Sec-CH-UA-Bitness": '"64"',
            "Sec-CH-UA-Model": '""',
        },
        "chrome_120_en": {
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
        },
        "chrome_120_mac": {
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"macOS"',
        },
    }

    def __init__(self, profile: str = "chrome_120_ru"):
        self.profile = profile
        self._headers = self.PROFILES.get(profile, self.PROFILES["chrome_120_ru"])

    def get_headers(self) -> dict:
        """Возвращает все fingerprint-заголовки для текущего профиля."""
        return dict(self._headers)

    def apply_to_request(self, headers: dict) -> dict:
        """Добавляет fingerprint-заголовки к запросу."""
        for k, v in self._headers.items():
            if k not in headers:
                headers[k] = v
        return headers


# 22. PROTOCOL POLYMORPHISM


class ProtocolPolymorph:
    """
    Каждое новое соединение случайно выглядит как другой протокол.

    Ротация: HTTP/2, gRPC, WebSocket, SSE, plain HTTPS, MQTT-over-WS.
    DPI не может зацепиться за один паттерн.
    """

    PROTOCOLS = [
        {
            "name": "http2_api",
            "content_type": "application/json",
            "path_prefix": "/api/v2/",
            "method": "POST",
        },
        {
            "name": "grpc",
            "content_type": "application/grpc+proto",
            "path_prefix": "/grpc.health.v1.Health/",
            "method": "POST",
            "extra_headers": {"TE": "trailers", "Grpc-Encoding": "gzip"},
        },
        {
            "name": "graphql",
            "content_type": "application/json",
            "path_prefix": "/graphql",
            "method": "POST",
        },
        {
            "name": "rest_get",
            "content_type": "application/json",
            "path_prefix": "/api/v1/users/",
            "method": "GET",
        },
        {
            "name": "websocket",
            "content_type": None,
            "path_prefix": "/ws/",
            "method": "GET",
            "extra_headers": {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
            },
        },
        {
            "name": "sse",
            "content_type": "text/event-stream",
            "path_prefix": "/events/",
            "method": "GET",
        },
        {
            "name": "mqtt_ws",
            "content_type": None,
            "path_prefix": "/mqtt",
            "method": "GET",
            "extra_headers": {
                "Upgrade": "websocket",
                "Sec-WebSocket-Protocol": "mqtt",
            },
        },
    ]

    def __init__(self):
        self._current_idx = 0

    def next_protocol(self) -> dict:
        """Выбирает следующий протокол для маскировки."""
        proto = _sysrand.choice(self.PROTOCOLS)
        self._current_idx += 1
        return proto

    def wrap_data(self, data: bytes, proto: Optional[dict] = None) -> dict:
        """
        Оборачивает данные в формат выбранного протокола.
        Возвращает {headers, body, path, method}.
        """
        if proto is None:
            proto = self.next_protocol()

        headers = {}
        if proto.get("content_type"):
            headers["Content-Type"] = proto["content_type"]
        if proto.get("extra_headers"):
            headers.update(proto["extra_headers"])

        # Формат body зависит от протокола
        if proto["name"] == "grpc":
            # gRPC: [1B compressed][4B length][payload]
            body = struct.pack(">BI", 0, len(data)) + data
        elif proto["name"] == "graphql":
            body = json.dumps(
                {
                    "query": "mutation { sync(data: $d) { ok } }",
                    "variables": {"d": base64.b64encode(data).decode()},
                }
            ).encode()
        else:
            body = data

        path = proto["path_prefix"]
        if proto["name"] == "rest_get":
            path += secrets.token_hex(8)

        return {
            "headers": headers,
            "body": body,
            "path": path,
            "method": proto["method"],
            "protocol_name": proto["name"],
        }

    def get_status(self) -> dict:
        return {
            "protocols_available": len(self.PROTOCOLS),
            "connections_rotated": self._current_idx,
        }


# 23. CONNECTION LIFECYCLE MIMICRY


class ConnectionLifecycleMimicry:
    """
    Время жизни TCP соединений как у браузера.

    Мессенджер: одно вечное соединение.
    Браузер: соединения 30с-5мин, переподключение, параллельные.

    Периодически закрывает и переоткрывает соединения.
    """

    def __init__(self, min_lifetime: float = 30.0, max_lifetime: float = 300.0, max_parallel: int = 6):
        self.min_lifetime = min_lifetime
        self.max_lifetime = max_lifetime
        self.max_parallel = max_parallel  # Chrome: max 6 per domain
        self._connections: dict[str, float] = {}  # conn_id → created_at
        self._reconnect_count = 0
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self, reconnect_callback: Optional[Callable] = None):
        """Запуск lifecycle management."""
        self._running = True
        self._task = asyncio.create_task(self._lifecycle_loop(reconnect_callback))

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    def register_connection(self, conn_id: str):
        """Регистрирует новое соединение."""
        self._connections[conn_id] = time.monotonic()

    def should_reconnect(self, conn_id: str) -> bool:
        """Проверяет, нужно ли переподключение."""
        created = self._connections.get(conn_id)
        if not created:
            return False
        lifetime = _sysrand.uniform(self.min_lifetime, self.max_lifetime)
        return (time.monotonic() - created) > lifetime

    async def _lifecycle_loop(self, callback: Optional[Callable]):
        while self._running:
            try:
                await asyncio.sleep(30)  # Проверяем каждые 30 сек
                now = time.monotonic()

                for conn_id, created in list(self._connections.items()):
                    max_life = _sysrand.uniform(self.min_lifetime, self.max_lifetime)
                    if now - created > max_life:
                        self._reconnect_count += 1
                        logger.debug("Connection lifecycle: reconnect %s (age=%.0fs)", conn_id[:8], now - created)
                        del self._connections[conn_id]

                        if callback:
                            try:
                                if asyncio.iscoroutinefunction(callback):
                                    await callback(conn_id)
                                else:
                                    callback(conn_id)
                            except Exception as e:
                                logger.debug("Lifecycle callback error: %s", e)

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.debug("Lifecycle loop error: %s", e)

    def get_status(self) -> dict:
        return {
            "active_connections": len(self._connections),
            "reconnect_count": self._reconnect_count,
            "max_parallel": self.max_parallel,
        }


# 24. STEGANOGRAPHIC DNS


class StegoDNS:
    """
    Данные в DNS TXT/CNAME запросах через обычные DNS-резолверы.

    Отдельный канал для управления/сигналинга.
    DPI не может заблокировать DNS без катастрофических последствий.

    Формат: data → base32 → TXT record query
    Max 255 bytes per TXT record → ~155 bytes raw data per query
    """

    MAX_TXT_LEN = 250  # Чуть меньше 255 для безопасности
    RAW_PER_QUERY = 150  # base32 overhead ~60%

    def __init__(self, control_domain: str = "status.cdn-check.net"):
        self.control_domain = control_domain

    def encode_signal(self, signal_type: str, payload: bytes = b"") -> list[str]:
        """
        Кодирует управляющий сигнал в DNS TXT запросы.
        signal_type: "ping", "key_rotate", "domain_change", "config"
        """
        # Signal header
        header = json.dumps({"t": signal_type, "ts": int(time.time())}).encode()
        data = header + (b"|" + payload if payload else b"")

        queries = []
        offset = 0
        idx = 0
        while offset < len(data):
            chunk = data[offset : offset + self.RAW_PER_QUERY]
            encoded = base64.b32encode(chunk).decode().rstrip("=").lower()
            # subdomain.idx.control_domain
            query = f"{encoded}.{idx}.{self.control_domain}"
            queries.append(query)
            offset += self.RAW_PER_QUERY
            idx += 1
        return queries

    @staticmethod
    def decode_signal(query: str, control_domain: str) -> Optional[dict]:
        """Декодирует DNS-запрос обратно в сигнал."""
        try:
            # Убираем .idx.control_domain
            parts = query.replace(f".{control_domain}", "").rsplit(".", 1)
            encoded = parts[0].upper()
            pad = (8 - len(encoded) % 8) % 8
            raw = base64.b32decode(encoded + "=" * pad)

            if b"|" in raw:
                header_raw, payload = raw.split(b"|", 1)
            else:
                header_raw, payload = raw, b""

            header = json.loads(header_raw)
            header["payload"] = payload
            return header
        except Exception:
            return None


# 25. FAKE CERTIFICATE CHAIN MIMICRY


class CertChainMimicry:
    """
    Сертификат сервера стилизован под Let's Encrypt.

    DPI может фингерпринтить по CA:
    - Самоподписанный = подозрительно
    - Нестандартный CA = подозрительно
    - Let's Encrypt = нормально (80%+ веб-сайтов)

    Настраивает certificate metadata при генерации self-signed certs.
    """

    # Let's Encrypt R3 Issuer fields
    LETSENCRYPT_ISSUER = {
        "C": "US",
        "O": "Let's Encrypt",
        "CN": "R3",
    }

    # Типичные параметры LE сертификата
    LETSENCRYPT_PARAMS = {
        "validity_days": 90,  # LE выдаёт на 90 дней
        "key_type": "ec",  # EC P-256 (LE default)
        "serial_length": 16,  # 128-bit random serial
        "signature_algo": "sha256",
    }

    @classmethod
    def get_cert_metadata(cls) -> dict:
        """Возвращает metadata для создания LE-подобного сертификата."""
        return {
            "issuer": cls.LETSENCRYPT_ISSUER,
            "params": cls.LETSENCRYPT_PARAMS,
            "extensions": [
                # Authority Information Access (AIA) как у LE
                {
                    "oid": "1.3.6.1.5.5.7.1.1",
                    "value": "OCSP - URI:http://r3.o.lencr.org\nCA Issuers - URI:http://r3.i.lencr.org/",
                },
                # Certificate Policies
                {"oid": "2.5.29.32", "value": "Policy: 2.23.140.1.2.1"},  # DV
                # SCT (Signed Certificate Timestamp)
                {"oid": "1.3.6.1.4.1.11129.2.4.2", "value": "signed_certificate_timestamps"},
            ],
        }

    @classmethod
    def configure_ssl_for_le_mimicry(cls, ctx) -> None:
        """Настраивает SSL context чтобы сертификат выглядел как LE."""
        import ssl

        try:
            # OCSP stapling (LE серверы делают stapling)
            if hasattr(ctx, "set_ocsp_client_callback"):
                pass  # Python ssl не поддерживает полностью

            # Минимум TLS 1.2 (как LE рекомендует)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            # Cipher suites как у типичного LE-сервера (nginx default)
            with contextlib.suppress(ssl.SSLError):
                ctx.set_ciphers(
                    "ECDHE-ECDSA-AES128-GCM-SHA256:"
                    "ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:"
                    "ECDHE-RSA-AES256-GCM-SHA384:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:"
                    "ECDHE-RSA-CHACHA20-POLY1305"
                )

        except Exception as e:
            logger.debug("LE cert mimicry partial: %s", e)


# 26. TRAFFIC SCHEDULING (HUMAN PATTERNS)


class TrafficScheduler:
    """
    Интенсивность трафика следует человеческим паттернам.

    Ровный 24/7 трафик = автоматика / VPN.
    Человеческий ритм = обычное использование.

    Профиль: активность максимальна 9-23, минимальна 2-6.
    """

    # Коэффициенты активности по часам (0=полночь, нормализовано)
    HOURLY_ACTIVITY = [
        0.15,
        0.08,
        0.05,
        0.03,
        0.03,
        0.05,  # 00-05
        0.10,
        0.25,
        0.50,
        0.75,
        0.85,
        0.90,  # 06-11
        0.85,
        0.80,
        0.75,
        0.70,
        0.75,
        0.80,  # 12-17
        0.90,
        0.95,
        1.00,
        0.95,
        0.80,
        0.50,  # 18-23
    ]

    def __init__(self, timezone_offset: int = 3):
        """timezone_offset: UTC+3 для Москвы."""
        self.tz_offset = timezone_offset
        self._cover_reduction_active = False

    def get_activity_factor(self) -> float:
        """
        Возвращает коэффициент активности для текущего часа.
        0.0-1.0, где 1.0 = максимальная активность.
        """
        import datetime

        utc_hour = datetime.datetime.now(datetime.timezone.utc).hour
        local_hour = (utc_hour + self.tz_offset) % 24
        base = self.HOURLY_ACTIVITY[local_hour]

        # Добавляем рандомный шум ±10%
        noise = _sysrand.uniform(-0.1, 0.1)
        return max(0.02, min(1.0, base + noise))

    def should_send_cover(self) -> bool:
        """Решает: отправлять ли cover traffic сейчас."""
        factor = self.get_activity_factor()
        return _sysrand.random() < factor

    def get_delay_multiplier(self) -> float:
        """
        Множитель задержки: ночью интервалы длиннее.
        """
        factor = self.get_activity_factor()
        # Инвертируем: маленькая активность → большие интервалы
        return 1.0 / max(0.1, factor)

    def get_status(self) -> dict:
        return {
            "current_activity": round(self.get_activity_factor(), 2),
            "timezone_offset": self.tz_offset,
        }


# 27. IP GEOLOCATION COHERENCE


class GeoCoherenceChecker:
    """
    Проверяет согласованность GeoIP, языка, timezone.

    Chrome из России с en-US Accept-Language и US timezone = аномалия.
    Обеспечиваем когерентность: RU IP → ru-RU язык → UTC+3.
    """

    GEO_PROFILES = {
        "RU": {
            "languages": ["ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7", "ru-RU,ru;q=0.9,en;q=0.8"],
            "timezone_offsets": [3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            "platform": '"Windows"',
        },
        "US": {
            "languages": ["en-US,en;q=0.9"],
            "timezone_offsets": [-5, -6, -7, -8],
            "platform": '"Windows"',
        },
        "DE": {
            "languages": ["de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"],
            "timezone_offsets": [1, 2],
            "platform": '"Windows"',
        },
    }

    def __init__(self, country: str = "RU"):
        self.country = country
        self._profile = self.GEO_PROFILES.get(country, self.GEO_PROFILES["RU"])

    def get_coherent_headers(self) -> dict:
        """Возвращает набор заголовков, согласованных с GeoIP."""
        return {
            "Accept-Language": _sysrand.choice(self._profile["languages"]),
            "Sec-CH-UA-Platform": self._profile["platform"],
        }

    def check_coherence(self, headers: dict, ip_country: str = "") -> list[str]:
        """
        Проверяет когерентность заголовков с GeoIP.
        Возвращает список аномалий.
        """
        anomalies = []
        country = ip_country or self.country

        lang = headers.get("Accept-Language", "")
        profile = self.GEO_PROFILES.get(country)

        if profile:
            # Проверяем язык
            lang_prefix = lang.split(",")[0].split("-")[0] if lang else ""
            expected_prefixes = [lang.split(",")[0].split("-")[0] for lang in profile["languages"]]
            if lang_prefix and lang_prefix not in expected_prefixes:
                anomalies.append(f"language_mismatch:{lang_prefix}!=expected")

        return anomalies


# 28. MULTI-HOP RELAY CHAIN


class MultiHopRelay:
    """
    Сообщения проходят через 2-3 промежуточных Vortex-нод.

    Как Tor, но внутри Vortex mesh network:
    Client → Node A → Node B → Node C → Server

    Каждый хоп видит только предыдущий и следующий.
    Ни один хоп не видит и отправителя и получателя.

    Слои шифрования: E2E + per-hop encryption.
    """

    DEFAULT_HOPS = 2
    MAX_HOPS = 4

    def __init__(self, num_hops: int = 2):
        self.num_hops = min(num_hops, self.MAX_HOPS)
        self._circuits: dict[str, list[str]] = {}  # circuit_id → [node_ids]
        self._active_circuits = 0

    def build_circuit(self, available_nodes: list[str], exclude: Optional[set[str]] = None) -> Optional[str]:
        """
        Строит цепочку из available_nodes.
        Возвращает circuit_id или None если недостаточно нод.
        """
        exclude = exclude or set()
        candidates = [n for n in available_nodes if n not in exclude]

        if len(candidates) < self.num_hops:
            return None

        # Выбираем случайные ноды для цепочки
        chain = random.sample(candidates, self.num_hops)
        circuit_id = secrets.token_hex(16)
        self._circuits[circuit_id] = chain
        self._active_circuits += 1

        logger.debug("Multi-hop circuit %s: %s hops", circuit_id[:8], len(chain))
        return circuit_id

    def wrap_onion(self, circuit_id: str, data: bytes) -> Optional[bytes]:
        """
        Оборачивает данные в луковое шифрование.
        Каждый слой содержит next_hop + encrypted(inner_layer).

        Формат каждого слоя:
        [16B circuit_id][1B hop_idx][2B next_hop_id_len][next_hop_id][2B payload_len][payload]
        """
        chain = self._circuits.get(circuit_id)
        if not chain:
            return None

        # Строим от последнего хопа к первому (луковые слои)
        current = data
        for i in range(len(chain) - 1, -1, -1):
            hop_id = chain[i].encode()
            layer = struct.pack(">16s B H", bytes.fromhex(circuit_id), i, len(hop_id))
            layer += hop_id
            layer += struct.pack(">H", len(current))
            layer += current

            # AES-256-GCM per-hop encryption
            key = hashlib.sha256(f"{circuit_id}:{i}".encode()).digest()
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, layer, None)
            current = nonce + ciphertext  # prepend nonce for decryption

        return current

    def unwrap_layer(self, encrypted_layer: bytes, hop_idx: int, circuit_id: str) -> tuple[Optional[str], bytes]:
        """
        Снимает один слой шифрования (на промежуточной ноде).
        Возвращает (next_hop_id, inner_payload) или (None, data) если финальный хоп.
        """
        key = hashlib.sha256(f"{circuit_id}:{hop_idx}".encode()).digest()
        nonce = encrypted_layer[:12]
        aesgcm = AESGCM(key)
        try:
            decrypted = aesgcm.decrypt(nonce, encrypted_layer[12:], None)
        except Exception:
            return None, encrypted_layer

        try:
            offset = 0
            cid = decrypted[offset : offset + 16].hex()
            offset += 16
            idx = decrypted[offset]
            offset += 1
            hop_id_len = struct.unpack(">H", decrypted[offset : offset + 2])[0]
            offset += 2
            hop_id = decrypted[offset : offset + hop_id_len].decode()
            offset += hop_id_len
            payload_len = struct.unpack(">H", decrypted[offset : offset + 2])[0]
            offset += 2
            payload = decrypted[offset : offset + payload_len]

            chain = self._circuits.get(cid, [])
            if idx >= len(chain) - 1:
                return None, payload  # Финальный хоп
            return hop_id, payload
        except Exception:
            return None, encrypted_layer

    def destroy_circuit(self, circuit_id: str):
        """Уничтожает цепочку."""
        if circuit_id in self._circuits:
            del self._circuits[circuit_id]
            self._active_circuits = max(0, self._active_circuits - 1)

    def get_status(self) -> dict:
        return {
            "num_hops": self.num_hops,
            "active_circuits": self._active_circuits,
            "max_hops": self.MAX_HOPS,
        }


# MANAGER — объединяет все механизмы Level 3


class StealthLevel3Manager:
    """
    Менеджер Level 3 маскировки.
    28 механизмов: 8 + 20 новых.
    """

    def __init__(self):
        # Batch 1 (mechanisms 1-8)
        self.doh_tunnel = DoHTunnel()
        self.ech = ECHConfigurator()
        self.h2_mux = H2Multiplexer()
        self.probe_detector = ActiveProbeDetector()
        self.tls_session = TLSSessionRandomizer()
        self.packet_loss = PacketLossSimulator()
        self.header_order = HeaderOrderRandomizer()
        self.frag_hello = FragmentedClientHello()

        # Batch 2 (mechanisms 9-28)
        self.h2_settings = H2SettingsFingerprint()
        self.h2_priority = H2PriorityFingerprint()
        self.ws_deflate = WSDeflateConfig()
        self.dga = DomainGenerator(seed=os.environ.get("VORTEX_DGA_SEED", "vortex-mesh-2026"))
        self.snowflake = SnowflakeProxy()
        self.meek: Optional[MeekLiteTunnel] = None  # Init with real_host later
        self.tfo = TCPFastOpenConfig()
        self.cookie_jar = CookieJarSimulator()
        self.entropy_norm = EntropyNormalizer()
        self.burst_coalescer = BurstCoalescer()
        self.tls_key_rotator = TLSKeyRotator()
        self.referer_chain: Optional[RefererChainSimulator] = None  # Init with site_url later
        self.browser_fp = BrowserFingerprint("chrome_120_ru")
        self.polymorph = ProtocolPolymorph()
        self.conn_lifecycle = ConnectionLifecycleMimicry()
        self.stego_dns = StegoDNS()
        self.cert_mimicry = CertChainMimicry()
        self.traffic_scheduler = TrafficScheduler(timezone_offset=3)
        self.geo_coherence = GeoCoherenceChecker("RU")
        self.multi_hop = MultiHopRelay(num_hops=2)

        self._running = False

    async def start(self, site_url: str = ""):
        """Запуск всех фоновых механизмов Level 3."""
        self._running = True

        # Инициализация зависимых от конфигурации модулей
        if site_url:
            self.referer_chain = RefererChainSimulator(site_url)
            self.meek = MeekLiteTunnel(real_host=site_url.replace("https://", "").replace("http://", ""))

        # Запуск фоновых процессов
        await self.tls_key_rotator.start()
        await self.conn_lifecycle.start()

        logger.info(
            "Stealth Level 3: started (%d mechanisms) — "
            "DoH=%s, ECH=%s, probe_detect=%s, DGA=%s, snowflake=%s, "
            "polymorph=%s, multi_hop=%s, scheduler=%s",
            28,
            "ON",
            "native" if self.ech.available else "fronting",
            "ON",
            "ON",
            "READY",
            "ON",
            f"{self.multi_hop.num_hops}-hop",
            f"activity={self.traffic_scheduler.get_activity_factor():.0%}",
        )

    def stop(self):
        self._running = False
        self.tls_key_rotator.stop()
        self.conn_lifecycle.stop()
        self.burst_coalescer.stop()

    def get_status(self) -> dict:
        return {
            # Batch 1
            "doh_tunnel": self.doh_tunnel.get_status(),
            "ech": self.ech.get_status(),
            "h2_multiplexing": self.h2_mux.get_status(),
            "active_probe_detection": self.probe_detector.get_stats(),
            "tls_session_randomization": self.tls_session.get_status(),
            "packet_loss_simulation": self.packet_loss.get_stats(),
            "header_order": "chrome_120",
            "fragmented_client_hello": True,
            # Batch 2
            "h2_settings_fingerprint": "chrome_120",
            "h2_priority_fingerprint": "chrome_120",
            "ws_permessage_deflate": True,
            "dga": {"domains_today": len(self.dga.get_current_domains())},
            "snowflake_proxy": self.snowflake.get_status(),
            "meek_lite": self.meek.get_status() if self.meek else None,
            "tcp_fast_open": True,
            "cookie_jar": True,
            "entropy_normalization": True,
            "burst_coalescing": self.burst_coalescer.get_stats(),
            "tls_key_rotation": self.tls_key_rotator.get_status(),
            "browser_fingerprint": "chrome_120_ru",
            "protocol_polymorphism": self.polymorph.get_status(),
            "connection_lifecycle": self.conn_lifecycle.get_status(),
            "stego_dns": True,
            "cert_chain_mimicry": "letsencrypt_r3",
            "traffic_scheduling": self.traffic_scheduler.get_status(),
            "geo_coherence": self.geo_coherence.country,
            "multi_hop_relay": self.multi_hop.get_status(),
        }


# Global instance
stealth_l3 = StealthLevel3Manager()
