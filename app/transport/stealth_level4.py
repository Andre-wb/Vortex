"""
app/transport/stealth_level4.py — Уровень 4: боевые протоколы и инфраструктура.

15 механизмов:

  A. Боевые протоколы (проверены в Китае/Иране/России):
    1. Reality (XTLS)     — ФЛАГМАН: заимствует TLS чужого сайта, ECDH-аутентификация
    2. Trojan             — данные внутри HTTPS, fallback на nginx
    3. ShadowTLS          — TLS handshake с google.com, данные к серверу
    4. NaïveProxy         — Chromium network stack fingerprint
    5. VMess              — legacy, снят с основного пути (см. RUST-MIGRATION.md)

  B. Инфраструктурная устойчивость:
    6. Tor Hidden Service — .onion адрес для сервера
    7. IPFS Distribution  — статика через IPFS
    8. Decentralized DNS  — ENS/Handshake домены
    9. Censorship Auto-Probe — авто-определение заблокированных транспортов
    10. CDN Workers Proxy — Cloudflare Workers KV store-and-forward

  C. Клиентская закалка:
    11. Service Worker Proxy — SW перехватывает запросы, применяет обфускацию
    12. WASM Crypto         — криптография в WebAssembly
    13. Oblivious HTTP      — relay скрывает IP клиента от сервера

  D. Мониторинг:
    14. Censorship Dashboard — панель блокировок по регионам
    15. Latency Probes       — пинги через все транспорты
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import logging
import math
import os
import random
import socket
import struct
import time
import zlib
from collections.abc import Awaitable, Callable
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app.config import Config
from app.security.secret_rotation import (
    previous,
    register_reload_hook,
    rotation_status,
)
from app.transport.reality_backend import RealityAuth

_sysrand = random.SystemRandom()

logger = logging.getLogger(__name__)


_PROBE_JITTER_LOW = 0.5
_PROBE_JITTER_HIGH = 1.8

_PAD_BUCKETS = (128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
_PAD_PROMOTE_PROBABILITY = 0.15
_PAD_TILE_STEP = 8192


def _jittered_delay(base: float, *, low: float = 0.5, high: float = 2.0) -> float:
    """
    Возвращает паузу для периодической задачи так, чтобы интервалы были
    memoryless, а не строго периодическими: наблюдатель не восстанавливает
    частоту по гистограмме. Усечённая экспонента на [base*low, base*high],
    сэмплированная через обратную функцию распределения — плотность непрерывна,
    без атомов на границах (обычный clamp свалил бы туда всю хвостовую массу и
    сам стал бы сигнатурой). Верхняя граница ограничивает худшую задержку
    обнаружения, нижняя убирает слишком частые пробы. Источник — random, не
    секрет: это расписание, а не криптоматериал.
    """
    s_lo = math.exp(-low)
    s_hi = math.exp(-high)
    return -base * math.log(s_lo - _sysrand.random() * (s_lo - s_hi))


# 1. V2RAY / VMESS PROTOCOL

_VMESS_KDF_SALT = b"VMess AEAD KDF"
_VMESS_CMD_KEY_MAGIC = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"


def _vmess_kdf(key: bytes, *path: bytes) -> bytes:
    def level(labels):
        if not labels:
            return lambda msg: hmac.new(_VMESS_KDF_SALT, msg, hashlib.sha256).digest()
        inner = level(labels[:-1])
        block = labels[-1].ljust(64, b"\x00")
        ipad = bytes(b ^ 0x36 for b in block)
        opad = bytes(b ^ 0x5C for b in block)
        return lambda msg: inner(opad + inner(ipad + msg))

    return level(path)(key)


class VMessProtocol:
    """
    VMess (VMessAEAD) — протокол V2Ray для обхода DPI.

    Формат запроса:
      [16B EAuID][2B+16B sealed length][8B nonce][headerLen+16B sealed header]
      [2B len][AES-128-GCM payload]

    EAuID = AES-128-ECB(KDF(cmd_key,"AES Auth ID Encryption"),
                         time || random || CRC32) — метка времени внутри,
    поэтому сервер читает её напрямую, без перебора окна и без HMAC-MD5.
    Header и его длина запечатаны AES-128-GCM на ключах/нонсах из KDF.

    DPI видит: случайные байты без паттерна.
    """

    VERSION = 1

    # Encryption methods
    AES_128_GCM = 0x03
    CHACHA20_POLY1305 = 0x04
    NONE = 0x05

    # Commands
    CMD_TCP = 0x01
    CMD_UDP = 0x02

    def __init__(self, uuid_hex: str = ""):
        """
        uuid_hex: 32-char hex string (VMess UUID).
        Если пусто — генерируем случайный.
        """
        if uuid_hex:
            self._uuid = bytes.fromhex(uuid_hex.replace("-", ""))
        else:
            self._uuid = os.urandom(16)
        self._request_body_key = os.urandom(16)
        self._request_body_iv = os.urandom(16)
        self._response_header = os.urandom(1)[0]
        self._cmd_key = hashlib.md5(self._uuid + _VMESS_CMD_KEY_MAGIC).digest()  # noqa: S324

    @property
    def uuid(self) -> str:
        return self._uuid.hex()

    AUTH_ID_WINDOW = 120

    def _create_auth_id(self, ts: int) -> bytes:
        payload = struct.pack(">q", ts) + os.urandom(4)
        payload += struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
        key = _vmess_kdf(self._cmd_key, b"AES Auth ID Encryption")[:16]
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())  # noqa: S305
        encryptor = cipher.encryptor()
        return encryptor.update(payload) + encryptor.finalize()

    def _verify_auth_id(self, auth_id: bytes) -> bool:
        key = _vmess_kdf(self._cmd_key, b"AES Auth ID Encryption")[:16]
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())  # noqa: S305
        decryptor = cipher.decryptor()
        decoded = decryptor.update(auth_id) + decryptor.finalize()
        if zlib.crc32(decoded[:12]) & 0xFFFFFFFF != struct.unpack(">I", decoded[12:16])[0]:
            return False
        ts = struct.unpack(">q", decoded[:8])[0]
        return abs(int(time.time()) - ts) <= self.AUTH_ID_WINDOW

    def _seal_header(self, header: bytes) -> bytes:
        auth_id = self._create_auth_id(int(time.time()))
        conn_nonce = os.urandom(8)

        length_key = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Key_Length", auth_id, conn_nonce)[:16]
        length_nonce = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Nonce_Length", auth_id, conn_nonce)[:12]
        sealed_length = AESGCM(length_key).encrypt(length_nonce, struct.pack(">H", len(header)), auth_id)

        header_key = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Key", auth_id, conn_nonce)[:16]
        header_nonce = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Nonce", auth_id, conn_nonce)[:12]
        sealed_header = AESGCM(header_key).encrypt(header_nonce, header, auth_id)

        return auth_id + sealed_length + conn_nonce + sealed_header

    def _open_header(self, packet: bytes) -> Optional[tuple[bytes, int]]:
        if len(packet) < 16 + 18 + 8:
            return None
        auth_id = packet[:16]
        if not self._verify_auth_id(auth_id):
            return None

        sealed_length = packet[16:34]
        conn_nonce = packet[34:42]
        length_key = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Key_Length", auth_id, conn_nonce)[:16]
        length_nonce = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Nonce_Length", auth_id, conn_nonce)[:12]
        try:
            length_plain = AESGCM(length_key).decrypt(length_nonce, sealed_length, auth_id)
        except Exception:
            return None
        header_len = struct.unpack(">H", length_plain)[0]

        off = 42
        sealed_header = packet[off : off + header_len + 16]
        if len(sealed_header) != header_len + 16:
            return None
        header_key = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Key", auth_id, conn_nonce)[:16]
        header_nonce = _vmess_kdf(self._cmd_key, b"VMess Header AEAD Nonce", auth_id, conn_nonce)[:12]
        try:
            header_plain = AESGCM(header_key).decrypt(header_nonce, sealed_header, auth_id)
        except Exception:
            return None
        return header_plain, off + header_len + 16

    def encode_header(self, target_addr: str, target_port: int, encryption: int = 0x03) -> bytes:
        """
        Кодирует VMess request header.
        """
        # Request header (before encryption):
        # [1B version][16B body_iv][16B body_key][1B response_header]
        # [1B option][1B padding_len | security][1B reserved][1B command]
        # [2B port][1B address_type][address]
        # [random padding]

        header = struct.pack(">B", self.VERSION)
        header += self._request_body_iv
        header += self._request_body_key
        header += struct.pack(">B", self._response_header)

        # Option: 0x01 = standard, padding & security
        padding_len = _sysrand.randint(0, 15)
        option = 0x01  # standard
        header += struct.pack(">B", option)

        # P(4bit) | Sec(4bit)
        p_sec = (padding_len << 4) | (encryption & 0x0F)
        header += struct.pack(">B", p_sec)

        # Reserved
        header += b"\x00"

        # Command
        header += struct.pack(">B", self.CMD_TCP)

        # Port
        header += struct.pack(">H", target_port)

        # Address type + address
        try:
            socket.inet_pton(socket.AF_INET, target_addr)
            header += struct.pack(">B", 0x01)  # IPv4
            header += socket.inet_aton(target_addr)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, target_addr)
                header += struct.pack(">B", 0x03)  # IPv6
                header += socket.inet_pton(socket.AF_INET6, target_addr)
            except OSError:
                # Domain name
                addr_bytes = target_addr.encode()
                header += struct.pack(">B B", 0x02, len(addr_bytes))
                header += addr_bytes

        # Random padding
        if padding_len > 0:
            header += os.urandom(padding_len)

        # FNV1a hash for integrity
        fnv = self._fnv1a_32(header)
        header += struct.pack(">I", fnv)

        return header

    def encode_packet(self, data: bytes, target_addr: str = "127.0.0.1", target_port: int = 443) -> bytes:
        """Полный VMess пакет: sealed header (VMessAEAD) + AES-128-GCM payload."""
        header = self.encode_header(target_addr, target_port)
        sealed = self._seal_header(header)

        nonce = self._request_body_iv[:12]
        encrypted_payload = AESGCM(self._request_body_key).encrypt(nonce, data, None)
        payload_frame = struct.pack(">H", len(encrypted_payload)) + encrypted_payload

        return sealed + payload_frame

    def decode_packet(self, packet: bytes) -> Optional[bytes]:
        """Декодирует VMess пакет (серверная сторона)."""
        opened = self._open_header(packet)
        if opened is None:
            return None
        header, offset = opened

        body_iv = header[1:17]
        body_key = header[17:33]

        if offset + 2 > len(packet):
            return None
        payload_len = struct.unpack(">H", packet[offset : offset + 2])[0]
        encrypted_payload = packet[offset + 2 : offset + 2 + payload_len]
        if len(encrypted_payload) < 16:
            return None

        try:
            return AESGCM(body_key).decrypt(body_iv[:12], encrypted_payload, None)
        except Exception:
            return None

    @staticmethod
    def _fnv1a_32(data: bytes) -> int:
        h = 0x811C9DC5
        for b in data:
            h ^= b
            h = (h * 0x01000193) & 0xFFFFFFFF
        return h

    def get_status(self) -> dict:
        return {
            "protocol": "vmess",
            "version": self.VERSION,
            "uuid": self.uuid[:8] + "...",
            "auth": "aead",
            "encryption": "aes-128-gcm",
        }


# 2. SHADOWTLS — TLS handshake с разрешённым сервером


class ShadowTLS:
    """
    ShadowTLS v3: выполняет настоящий TLS handshake с whitelisted сервером
    (google.com, cloudflare.com), затем переключает поток данных на Vortex.

    DPI видит:
    1. TCP SYN → Vortex IP
    2. TLS ClientHello с SNI = www.google.com
    3. TLS ServerHello от google.com (реальный!)
    4. Encrypted Application Data (неотличимо от Google)

    Механизм:
    - Сервер прозрачно проксирует поток к реальному google.com, разбирая его
      по TLS-записям, и параллельно ищет switch-запись от клиента.
    - Switch-запись — TLS Application Data (0x17) с payload
      session_id‖HMAC(session_id): подделать без ключа нельзя, настоящий клиент
      её не шлёт (тогда поток остаётся прозрачным проксёром — активное
      зондирование получает настоящий google).
    - Момент переключения не привязан к таймеру: совпадает с завершением
      handshake и колеблется с RTT, без фиксированной отсечки-сигнатуры.
    """

    # Whitelisted серверы для TLS handshake
    HANDSHAKE_TARGETS = [
        ("www.google.com", 443),
        ("www.microsoft.com", 443),
        ("cloudflare.com", 443),
        ("www.apple.com", 443),
        ("www.amazon.com", 443),
    ]

    SESSION_ID_LEN = 16
    HMAC_MARKER_LEN = 8
    _TLS_CONTENT_TYPES = (0x14, 0x15, 0x16, 0x17)
    _MAX_TLS_RECORD = 16640

    def __init__(self, password: str = ""):
        self._explicit_password = password
        self.reload_secrets()

    def reload_secrets(self) -> None:
        """Перечитывает пароль из конфигурации (вызывается после ротации)."""
        if self._explicit_password:
            self._password = self._explicit_password.encode()
            self._prev_password = b""
        else:
            self._password = Config.SHADOWTLS_PASSWORD.encode()
            self._prev_password = previous("SHADOWTLS_PASSWORD").encode()
        self._hmac_key = self._derive_key(self._password)
        self._prev_hmac_key = self._derive_key(self._prev_password) if self._prev_password else b""

    @staticmethod
    def _derive_key(password: bytes) -> bytes:
        return hashlib.sha256(b"shadowtls-hmac:" + password).digest()

    def get_handshake_target(self) -> tuple[str, int]:
        """Выбирает случайный сервер для TLS handshake."""
        return _sysrand.choice(self.HANDSHAKE_TARGETS)

    def generate_switch_marker(self, session_id: bytes) -> bytes:
        """
        Генерирует HMAC-маркер для переключения с TLS на данные.
        Этот маркер вставляется в начало Application Data после handshake.
        """
        h = hmac.new(self._hmac_key, session_id, hashlib.sha256)
        return h.digest()[: self.HMAC_MARKER_LEN]

    def verify_switch_marker(self, data: bytes, session_id: bytes) -> bool:
        """
        Проверяет HMAC-маркер переключения.
        Принимается также маркер на предыдущем пароле — до следующей ротации,
        пока клиенты не получили новый.
        """
        if len(data) < self.HMAC_MARKER_LEN:
            return False
        marker = data[: self.HMAC_MARKER_LEN]
        if hmac.compare_digest(marker, self.generate_switch_marker(session_id)):
            return True
        if not self._prev_hmac_key:
            return False
        prev = hmac.new(self._prev_hmac_key, session_id, hashlib.sha256).digest()[: self.HMAC_MARKER_LEN]
        return hmac.compare_digest(marker, prev)

    async def server_handshake_proxy(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> Optional[bytes]:
        """
        Серверная сторона: прозрачно проксирует поток к whitelisted серверу,
        разбирая его по TLS-записям, и ждёт switch-запись от клиента.

        Обе стороны релеятся по целым TLS-записям, поэтому при переключении
        отмена релея сервер→клиент приходит только на границе записи — клиент
        никогда не получает обрезанную запись и его парсер кадров не рассинхронён.
        Записи handshake форвардятся к реальному серверу как есть, поэтому DPI
        видит полный настоящий handshake; switch-запись наружу не уходит.
        Переключение не привязано к таймеру — момент совпадает с завершением
        handshake и колеблется с RTT.

        Клиентский контракт: switch-запись (session_id‖HMAC(session_id) в
        Application Data) шлётся первой после завершения handshake, отдельной
        записью; ответные NewSessionTicket до этого момента клиент игнорирует.
        Клиент добивает switch-запись padding'ом до правдоподобного размера
        Application Data — иначе одинокая 24-байтная запись сама станет приметой
        в точке переключения.

        Возвращает session_id, либо None, если клиент закрылся или это не наш
        клиент — тогда поток так и остаётся прозрачным проксёром к серверу.
        """
        target_host, target_port = self.get_handshake_target()
        remote_writer = None
        to_client = None

        async def pump(reader, writer):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass

        try:
            remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
            to_client = asyncio.create_task(self._pump_records(remote_reader, client_writer))

            while True:
                try:
                    header = await client_reader.readexactly(5)
                except (asyncio.IncompleteReadError, ConnectionError):
                    return None

                length = int.from_bytes(header[3:5], "big")
                if header[0] not in self._TLS_CONTENT_TYPES or header[1] != 0x03 or length > self._MAX_TLS_RECORD:
                    remote_writer.write(header)
                    await remote_writer.drain()
                    await pump(client_reader, remote_writer)
                    return None

                try:
                    payload = await client_reader.readexactly(length)
                except (asyncio.IncompleteReadError, ConnectionError):
                    return None

                session_id = self._match_switch_record(header[0], payload)
                if session_id is not None:
                    logger.debug("ShadowTLS: switch record received, entering data mode")
                    return session_id

                remote_writer.write(header + payload)
                await remote_writer.drain()

        except Exception as e:
            logger.debug("ShadowTLS handshake error: %s", e)
            return None
        finally:
            if to_client is not None and not to_client.done():
                to_client.cancel()
                await asyncio.gather(to_client, return_exceptions=True)
            if remote_writer is not None and not remote_writer.is_closing():
                remote_writer.close()

    async def _pump_records(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Релеит поток сервер→клиент целыми TLS-записями. Каждая запись пишется
        одним write, поэтому отмена задачи (при switch) не оставляет клиенту
        обрезанную запись — теряется максимум одна целая запись (например
        NewSessionTicket), а не половина, что рассинхронило бы парсер кадров.
        """
        try:
            while True:
                try:
                    header = await reader.readexactly(5)
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                length = int.from_bytes(header[3:5], "big")
                if header[0] not in self._TLS_CONTENT_TYPES or header[1] != 0x03 or length > self._MAX_TLS_RECORD:
                    return
                try:
                    payload = await reader.readexactly(length)
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                writer.write(header + payload)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass

    def _match_switch_record(self, content_type: int, payload: bytes) -> Optional[bytes]:
        """
        Возвращает session_id, если запись — валидная switch-запись: Application
        Data с аутентичным HMAC на первых SESSION_ID_LEN+HMAC_MARKER_LEN байтах.
        Payload может быть длиннее (padding после маркера) — проверяется префикс.
        """
        if content_type != 0x17:
            return None
        head = self.SESSION_ID_LEN + self.HMAC_MARKER_LEN
        if len(payload) < head:
            return None
        session_id = payload[: self.SESSION_ID_LEN]
        if self.verify_switch_marker(payload[self.SESSION_ID_LEN : head], session_id):
            return session_id
        return None

    def _session_key(self, session_id: bytes, label: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id,
            info=label,
        ).derive(self._hmac_key)

    def new_session(self, session_id: bytes, *, server: bool) -> ShadowTLSSession:
        """
        Создаёт защищённую сессию поверх switched-потока. Ключи направлений
        разделены (c2s/s2c), поэтому детерминированный счётчик-nonce безопасен;
        запись нумеруется монотонно и номер входит в AAD: подменить или
        переставить запись нельзя, а пропуск записи рассинхронизирует счётчик
        и роняет расшифровку последующих фреймов.
        """
        c2s = self._session_key(session_id, b"shadowtls c2s")
        s2c = self._session_key(session_id, b"shadowtls s2c")
        if server:
            return ShadowTLSSession(key_send=s2c, key_recv=c2s)
        return ShadowTLSSession(key_send=c2s, key_recv=s2c)

    def get_status(self) -> dict:
        return {
            "protocol": "shadowtls_v3",
            "handshake_targets": len(self.HANDSHAKE_TARGETS),
            "marker_len": self.HMAC_MARKER_LEN,
        }


class ShadowTLSSession:
    """
    Защищённый поток данных ShadowTLS после switch: каждая запись — валидная
    TLS 1.3 application_data (0x17 0x03 0x03) с AEAD-телом. Nonce — монотонный
    счётчик записи (не передаётся, как implicit sequence в TLS 1.3), номер также
    входит в AAD: подменить или переставить запись нельзя, а пропуск записи
    рассинхронизирует счётчик и роняет расшифровку последующих фреймов.
    """

    TLS_RECORD_HEADER = b"\x17\x03\x03"
    TLS_RECORD_MAX = 16384
    _TAG_LEN = 16

    def __init__(self, key_send: bytes, key_recv: bytes):
        self._send = AESGCM(key_send)
        self._recv = AESGCM(key_recv)
        self._send_seq = 0
        self._recv_seq = 0

    @staticmethod
    def _nonce(seq: int) -> bytes:
        return seq.to_bytes(12, "big")

    def wrap(self, data: bytes) -> bytes:
        """Упаковывает данные в TLS-записи; крупнее 16 КБ — несколько записей."""
        chunk = self.TLS_RECORD_MAX - self._TAG_LEN
        out = bytearray()
        for i in range(0, max(len(data), 1), chunk):
            piece = data[i : i + chunk]
            header = self.TLS_RECORD_HEADER + struct.pack(">H", len(piece) + self._TAG_LEN)
            aad = header + struct.pack(">Q", self._send_seq)
            out += header + self._send.encrypt(self._nonce(self._send_seq), piece, aad)
            self._send_seq += 1
        return bytes(out)

    def unwrap(self, frame: bytes) -> Optional[bytes]:
        """Извлекает данные, проверяя непрерывность счётчика записей."""
        out = bytearray()
        pos = 0
        while pos + 5 <= len(frame):
            header = frame[pos : pos + 5]
            if header[:3] != self.TLS_RECORD_HEADER:
                return None
            body_len = struct.unpack(">H", header[3:5])[0]
            pos += 5
            if pos + body_len > len(frame) or body_len < self._TAG_LEN:
                return None
            aad = header + struct.pack(">Q", self._recv_seq)
            try:
                out += self._recv.decrypt(self._nonce(self._recv_seq), frame[pos : pos + body_len], aad)
            except Exception:
                return None
            self._recv_seq += 1
            pos += body_len
        if pos != len(frame):
            return None
        return bytes(out)


# 3. REALITY (XTLS) — проксирует реальный TLS сертификат


class RealityProtocol:
    """
    Reality (XTLS-Vision): сервер представляется настоящим сайтом.

    Принцип:
    1. DPI или active probe подключается к серверу
    2. Сервер отвечает РЕАЛЬНЫМ сертификатом от dest server (google.com)
    3. Если клиент НЕ знает секрет — получает реальный google.com
    4. Если клиент знает секрет — получает Vortex

    Нельзя определить: тот же IP, тот же сертификат, тот же TLS.

    Ключевое отличие от ShadowTLS: сервер сам выполняет TLS,
    используя ключи от реального сервера (через XTLS splice).
    """

    DEST_SERVERS = [
        "www.google.com",
        "www.microsoft.com",
        "dl.google.com",
        "www.apple.com",
        "cdn.jsdelivr.net",
    ]

    SHORT_ID_LEN = 8

    REALITY_AUTH_WINDOW_PAST = 120
    REALITY_AUTH_WINDOW_FUTURE = 30

    def __init__(self, private_key: Optional[X25519PrivateKey] = None, dest: str = "www.google.com"):
        """
        private_key: X25519 private key для REALITY handshake.
        dest: сервер-донор сертификата.
        """
        self._dest = dest
        raw_secret = None
        if private_key is not None:
            raw_secret = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self._auth = RealityAuth(
            raw_secret,
            self.REALITY_AUTH_WINDOW_PAST,
            self.REALITY_AUTH_WINDOW_FUTURE,
        )
        self._public_key = self._auth.public_key()

    def add_short_id(self, short_id: str) -> bool:
        """Добавляет разрешённый short_id клиента."""
        return self._auth.add_short_id(short_id)

    def remove_short_id(self, short_id: str) -> bool:
        """Отзывает short_id клиента."""
        return self._auth.remove_short_id(short_id)

    def generate_short_id(self) -> str:
        """Генерирует новый short_id для клиента."""
        return self._auth.generate_short_id()

    def build_client_hello_auth(self, short_id: str, server_public_raw: bytes) -> tuple[bytes, bytes]:
        """Собирает клиентский AEAD-конверт: (ephemeral_pub, session_id)."""
        return self._auth.build_client_hello_auth(short_id, server_public_raw)

    def verify_client_hello_auth(self, ephemeral_pub: bytes, session_id: bytes) -> tuple[bool, str]:
        """Проверяет конверт: свежесть, известность short_id, отсутствие повтора."""
        return self._auth.verify_client_hello_auth(ephemeral_pub, session_id)

    def is_reality_client(self, client_hello: bytes) -> tuple[bool, str]:
        """
        Аутентифицирует ClientHello REALITY-клиента.

        Ephemeral X25519 клиента берётся из key_share, session_id — AEAD-конверт
        (версия‖время‖short_id) на ключе ECDH(ephemeral, server_key). Подделать
        без публичного ключа сервера и свежего ECDH нельзя — активный пробинг
        получает только реальный dest-сайт.
        """
        return self._auth.is_reality_client(client_hello)

    TLS_RECORD_MAX = 16384

    async def _read_client_hello(self, reader: asyncio.StreamReader, timeout: float = 10.0) -> bytes:
        """Читает первую TLS-запись целиком по её длине — без рассинхронизации
        на фрагментированном ClientHello."""
        try:
            header = await asyncio.wait_for(reader.readexactly(5), timeout=timeout)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            return b""
        if header[0] != 0x16:
            return header
        rec_len = min(int.from_bytes(header[3:5], "big"), self.TLS_RECORD_MAX)
        try:
            body = await asyncio.wait_for(reader.readexactly(rec_len), timeout=timeout)
        except asyncio.IncompleteReadError as e:
            body = e.partial
        except (asyncio.TimeoutError, ConnectionError):
            body = b""
        return header + body

    async def handle_connection(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> Optional[str]:
        """
        Обработка входящего соединения. Читает ClientHello целиком (по длине
        TLS-записи), затем классифицирует. Наш клиент → short_id; чужой →
        прозрачный TCP-релей к dest и None. Аутентификация — свежий ECDH к
        ключу сервера, угадать short_id и получить зависшее соединение
        активный пробинг не может: ему отдаётся реальный dest-сайт.
        """
        client_hello = await self._read_client_hello(client_reader)
        if not client_hello:
            return None

        is_ours, short_id = self.is_reality_client(client_hello)
        if is_ours:
            logger.debug("Reality: authenticated client (sid=%s)", short_id)
            return short_id

        logger.debug("Reality: proxying to %s (not our client)", self._dest)
        remote_w = None
        try:
            remote_r, remote_w = await asyncio.open_connection(self._dest, 443, ssl=False)
            remote_w.write(client_hello)
            await remote_w.drain()

            async def _fwd(reader, writer):
                try:
                    while True:
                        chunk = await reader.read(8192)
                        if not chunk:
                            break
                        writer.write(chunk)
                        await writer.drain()
                except (ConnectionError, asyncio.CancelledError):
                    pass

            up = asyncio.create_task(_fwd(client_reader, remote_w))
            down = asyncio.create_task(_fwd(remote_r, client_writer))
            _, pending = await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
        except Exception as e:
            logger.debug("Reality handle error: %s", e)
        finally:
            if remote_w is not None and not remote_w.is_closing():
                remote_w.close()
            if not client_writer.is_closing():
                client_writer.close()
        return None

    def get_client_config(self) -> dict:
        """Конфигурация для клиента."""
        return {
            "protocol": "reality",
            "dest": self._dest,
            "public_key": base64.b64encode(self._public_key).decode(),
            "short_id": self.generate_short_id(),
            "fingerprint": "chrome",
            "spider_x": "/",
        }

    def get_status(self) -> dict:
        return {
            "protocol": "reality_xtls",
            "flagship": True,
            "auth": "x25519-ecdh-aead",
            "envelope_version": self._auth.envelope_version,
            "dest_server": self._dest,
            "authorized_clients": self._auth.authorized_count(),
        }


# 4. TROJAN PROTOCOL


class TrojanProtocol:
    """
    Trojan: данные внутри обычного HTTPS.

    Формат:
    [56B hex(SHA224(password))][CRLF][1B cmd][address][2B port][CRLF][payload]

    Если пароль неверный — сервер работает как обычный nginx.
    Active probe получает реальную веб-страницу.
    """

    CMD_CONNECT = 0x01
    CMD_UDP = 0x03

    def __init__(self, password: str = ""):
        self._explicit_password = password
        self._extra_hashes: set[str] = set()
        self.reload_secrets()

    def reload_secrets(self) -> None:
        """Перечитывает пароль из конфигурации (вызывается после ротации)."""
        self._password = self._explicit_password or Config.TROJAN_PASSWORD
        self._password_hash = hashlib.sha224(self._password.encode()).hexdigest()
        self._authorized_hashes = {self._password_hash} | self._extra_hashes
        # Предыдущий пароль принимается до следующей ротации.
        prev = "" if self._explicit_password else previous("TROJAN_PASSWORD")
        if prev:
            self._authorized_hashes.add(hashlib.sha224(prev.encode()).hexdigest())

    def add_password(self, password: str):
        """Добавляет дополнительный пароль."""
        h = hashlib.sha224(password.encode()).hexdigest()
        self._extra_hashes.add(h)
        self._authorized_hashes.add(h)

    def encode_request(self, data: bytes, target_addr: str = "127.0.0.1", target_port: int = 443) -> bytes:
        """
        Кодирует Trojan-запрос.
        """
        # Password hash (56 hex chars)
        request = self._password_hash.encode()
        request += b"\r\n"

        # Command
        request += struct.pack(">B", self.CMD_CONNECT)

        # Address
        try:
            socket.inet_pton(socket.AF_INET, target_addr)
            request += struct.pack(">B", 0x01)  # IPv4
            request += socket.inet_aton(target_addr)
        except OSError:
            addr_bytes = target_addr.encode()
            request += struct.pack(">B B", 0x03, len(addr_bytes))
            request += addr_bytes

        # Port
        request += struct.pack(">H", target_port)
        request += b"\r\n"

        # Payload
        request += data
        return request

    def decode_request(self, data: bytes) -> Optional[tuple[str, bytes]]:
        """
        Декодирует Trojan-запрос.
        Возвращает (password_hash, payload) или None если формат неверный.
        """
        if len(data) < 58:  # 56 + CRLF
            return None

        # Extract password hash
        crlf_idx = data.find(b"\r\n")
        if crlf_idx < 0 or crlf_idx != 56:
            return None

        pwd_hash = data[:56].decode("ascii", errors="replace")

        if pwd_hash not in self._authorized_hashes:
            return None

        # Parse command + address (skip for simplicity, extract payload)
        # After second CRLF is the payload
        rest = data[58:]
        second_crlf = rest.find(b"\r\n")
        if second_crlf < 0:
            return pwd_hash, b""

        payload = rest[second_crlf + 2 :]
        return pwd_hash, payload

    def is_trojan_request(self, first_bytes: bytes) -> bool:
        """
        Быстрая проверка: это Trojan-запрос?
        Первые 56 байт должны быть hex-символами.
        """
        if len(first_bytes) < 58:
            return False
        try:
            candidate = first_bytes[:56].decode("ascii")
            int(candidate, 16)  # Должен быть валидный hex
            return first_bytes[56:58] == b"\r\n"
        except (ValueError, UnicodeDecodeError):
            return False

    def get_status(self) -> dict:
        return {
            "protocol": "trojan",
            "authorized_passwords": len(self._authorized_hashes),
            "fallback": "nginx_cover_site",
        }


# 5. NAIVEPROXY — Chromium network stack fingerprint


class NaiveProxyConfig:
    """
    NaïveProxy: использует сетевой стек Chromium для идеального fingerprint.

    NaïveProxy = forked Chrome network stack → каждый TLS параметр
    идентичен настоящему Chrome (JA3, JA4, HTTP/2 settings, всё).

    Серверная часть: Caddy с naive plugin.
    Клиентская часть: naiveproxy binary.

    Здесь — конфигуратор для Vortex-интеграции.
    """

    CADDY_CONFIG_TEMPLATE = """\
{{
    order forward_proxy before file_server
    servers {{
        protocols h1 h2
    }}
}}

:{port} {{
    tls {email} {{
        protocols tls1.2 tls1.3
        curves x25519 secp256r1 secp384r1
    }}

    forward_proxy {{
        basic_auth {username} {password}
        hide_ip
        hide_via
        probe_resistance {probe_domain}
    }}

    reverse_proxy {backend_url} {{
        header_up Host {{host}}
        header_up X-Real-IP {{remote_host}}
    }}

    file_server {{
        root /var/www/html
    }}
}}
"""

    def __init__(
        self, port: int = 443, backend_url: str = "", server_host: str = "", username: str = "", password: str = ""
    ):
        self.port = port
        self.backend_url = backend_url
        self._server_host = server_host
        self._explicit_username = username
        self._explicit_password = password
        self.reload_secrets()

    def reload_secrets(self) -> None:
        """Перечитывает имя, пароль и probe-домен (вызывается после ротации)."""
        self._username = self._explicit_username or Config.NAIVE_USERNAME
        self._password = self._explicit_password or Config.NAIVE_PASSWORD
        self._probe_domain = Config.NAIVE_PROBE_DOMAIN

    def generate_caddy_config(
        self, username: str = "", password: str = "", email: str = "admin@example.com", probe_domain: str = ""
    ) -> str:
        """Генерирует Caddyfile для NaïveProxy."""
        pwd = password or self._password
        return self.CADDY_CONFIG_TEMPLATE.format(
            port=self.port,
            email=email,
            username=username or self._username,
            password=pwd,
            probe_domain=probe_domain or self._probe_domain,
            backend_url=self.backend_url or "http://127.0.0.1:8000",
        )

    def generate_client_config(self, server_host: str, username: str = "", password: str = "") -> dict:
        """Генерирует конфигурацию для naiveproxy клиента."""
        user = username or self._username
        pwd = password or self._password
        return {
            "listen": "socks://127.0.0.1:1080",
            "proxy": f"https://{user}:{pwd}@{server_host}:{self.port}",
            "log": "",
            "padding": True,
        }

    async def check_available(self, server_host: str = "", timeout: float = 5.0) -> bool:
        """
        Проверяет доступность NaiveProxy (Caddy forward_proxy).
        Отправляет HTTP CONNECT probe — ожидает 407 (Proxy Auth Required)
        или 200 при правильных credentials.
        """
        host = server_host or self._server_host
        if not host:
            return False
        try:
            import httpx

            # Caddy с forward_proxy при probe_resistance возвращает фейковую страницу
            # для неавторизованных запросов. Авторизованный CONNECT вернёт 200.
            proxy_url = f"https://{self._username}:{self._password}@{host}:{self.port}"
            async with httpx.AsyncClient(
                proxy=proxy_url,
                timeout=timeout,
            ) as client:
                resp = await client.get("https://www.google.com/generate_204")
                return resp.status_code in (200, 204)
        except Exception as e:
            logger.debug("NaiveProxy availability check failed: %s", e)
            return False

    async def forward_via_proxy(
        self, target_url: str, data: bytes, method: str = "POST", server_host: str = ""
    ) -> Optional[bytes]:
        """
        Пересылает запрос через NaiveProxy (HTTP CONNECT proxy).
        Использует Caddy forward_proxy как HTTPS прокси.
        """
        host = server_host or self._server_host
        if not host:
            logger.error("NaiveProxy: server_host not configured")
            return None

        proxy_url = f"https://{self._username}:{self._password}@{host}:{self.port}"
        try:
            import httpx

            async with httpx.AsyncClient(
                proxy=proxy_url,
                timeout=15.0,
            ) as client:
                if method.upper() == "POST":
                    resp = await client.post(target_url, content=data)
                else:
                    resp = await client.get(target_url)
                if resp.status_code == 200:
                    return resp.content
                logger.debug("NaiveProxy forward: status %d", resp.status_code)
                return None
        except Exception as e:
            logger.debug("NaiveProxy forward error: %s", e)
            return None

    def get_status(self) -> dict:
        return {
            "protocol": "naiveproxy",
            "port": self.port,
            "server_host": self._server_host or "not_configured",
            "fingerprint": "chrome_identical",
        }


# 6. TOR HIDDEN SERVICE


class TorHiddenService:
    """
    Управление Tor Hidden Service (.onion) для Vortex.

    Если IP заблокирован — .onion адрес работает через Tor.
    Сервер доступен даже без знания его IP.

    Требует установленный Tor на сервере.
    Класс управляет жизненным циклом процесса Tor:
    запуск, остановка, перезапуск, ожидание готовности .onion адреса.
    """

    TORRC_TEMPLATE = """\
# Vortex Tor Hidden Service Configuration
HiddenServiceDir {hidden_service_dir}
HiddenServicePort 80 127.0.0.1:{http_port}
HiddenServicePort 443 127.0.0.1:{https_port}

# Security settings
HiddenServiceVersion 3
HiddenServiceMaxStreams 100
HiddenServiceMaxStreamsCloseCircuit 1

# Allow only connections through Tor
SocksPort 0
"""

    HS_READY_TIMEOUT = 120
    HS_POLL_INTERVAL = 2.0

    def __init__(
        self,
        http_port: int = 8000,
        https_port: int = 8443,
        hidden_service_dir: str = "/var/lib/tor/vortex",
        tor_binary: str = "tor",
        torrc_path: str = "/etc/tor/vortex-torrc",
    ):
        self.http_port = http_port
        self.https_port = https_port
        self.hidden_service_dir = hidden_service_dir
        self._tor_binary = tor_binary
        self._torrc_path = torrc_path
        self._onion_address: Optional[str] = None
        self._process: Optional[asyncio.subprocess.Process] = None

    def generate_torrc(self) -> str:
        """Генерирует torrc конфигурацию."""
        return self.TORRC_TEMPLATE.format(
            hidden_service_dir=self.hidden_service_dir,
            http_port=self.http_port,
            https_port=self.https_port,
        )

    def _write_torrc(self) -> str:
        """Записывает torrc на диск, возвращает путь к файлу."""
        config = self.generate_torrc()
        os.makedirs(os.path.dirname(self._torrc_path), exist_ok=True)
        with open(self._torrc_path, "w") as f:
            f.write(config)
        logger.info("Tor: wrote torrc to %s", self._torrc_path)
        return self._torrc_path

    async def start(self) -> Optional[str]:
        """
        Запускает процесс Tor с конфигурацией hidden service.
        Ожидает появления hostname файла с .onion адресом.
        Возвращает .onion адрес или None при ошибке.
        """
        if self.is_running():
            logger.warning("Tor: already running (pid=%s)", self._process.pid)
            return self._onion_address

        torrc_path = self._write_torrc()

        try:
            self._process = await asyncio.create_subprocess_exec(
                self._tor_binary,
                "-f",
                torrc_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            logger.info("Tor: started process (pid=%s)", self._process.pid)
        except FileNotFoundError:
            logger.error("Tor: binary '%s' not found — is Tor installed?", self._tor_binary)
            return None
        except Exception as e:
            logger.error("Tor: failed to start process: %s", e)
            return None

        onion = await self._wait_for_hostname()
        if onion:
            logger.info("Tor: hidden service ready at %s", onion)
        else:
            logger.error("Tor: hidden service did not become ready within %ds", self.HS_READY_TIMEOUT)
        return onion

    async def _wait_for_hostname(self) -> Optional[str]:
        """Поллит hostname файл до появления .onion адреса или таймаута."""
        elapsed = 0.0
        while elapsed < self.HS_READY_TIMEOUT:
            if self._process and self._process.returncode is not None:
                stderr_data = b""
                if self._process.stderr:
                    stderr_data = await self._process.stderr.read()
                logger.error(
                    "Tor: process exited with code %d: %s",
                    self._process.returncode,
                    stderr_data.decode(errors="replace")[:500],
                )
                return None

            addr = self.read_onion_address()
            if addr:
                return addr

            await asyncio.sleep(self.HS_POLL_INTERVAL)
            elapsed += self.HS_POLL_INTERVAL
        return None

    async def stop(self):
        """Останавливает процесс Tor (SIGTERM, затем SIGKILL по таймауту)."""
        if not self._process:
            return
        if self._process.returncode is not None:
            logger.debug("Tor: process already exited (code=%s)", self._process.returncode)
            self._process = None
            return

        logger.info("Tor: stopping process (pid=%s)", self._process.pid)
        self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.warning("Tor: process did not exit after SIGTERM, sending SIGKILL")
            self._process.kill()
            await self._process.wait()
        self._process = None

    async def restart(self) -> Optional[str]:
        """Перезапуск Tor: stop + start."""
        await self.stop()
        return await self.start()

    def is_running(self) -> bool:
        """Проверяет, запущен ли процесс Tor."""
        return self._process is not None and self._process.returncode is None

    def read_onion_address(self) -> Optional[str]:
        """Читает .onion адрес из файла (после запуска Tor)."""
        hostname_file = os.path.join(self.hidden_service_dir, "hostname")
        try:
            with open(hostname_file) as f:
                self._onion_address = f.read().strip()
                return self._onion_address
        except FileNotFoundError:
            return None

    @property
    def onion_address(self) -> Optional[str]:
        if not self._onion_address:
            self.read_onion_address()
        return self._onion_address

    def get_status(self) -> dict:
        return {
            "enabled": True,
            "running": self.is_running(),
            "pid": self._process.pid if self.is_running() else None,
            "onion_address": self.onion_address or "not_started",
            "http_port": self.http_port,
            "https_port": self.https_port,
        }


class IPFSDistributor:
    """
    Раздача статики и обновлений через IPFS.

    CID вычисляется как настоящий CIDv1 (raw-кодек, sha2-256, multibase base32):
    для одноблочного контента он совпадает с результатом
    `ipfs add --cid-version=1 --raw-leaves`. Но валидный CID сам по себе не
    раздаётся — пока блок не запинен на реальном узле, любой gateway отдаёт 404.
    Поэтому публикация идёт на узел Kubo (IPFS_API_URL) и запоминает CID,
    который вернул демон; без узла CID лишь вычисляется и помечается unpinned.
    """

    GATEWAYS = [
        "https://ipfs.io/ipfs/",
        "https://dweb.link/ipfs/",
        "https://gateway.pinata.cloud/ipfs/",
        "https://w3s.link/ipfs/",
    ]

    def __init__(self):
        self._published: dict[str, dict] = {}
        self._gateway_idx = 0

    def _next_gateway(self) -> str:
        gw = self.GATEWAYS[self._gateway_idx % len(self.GATEWAYS)]
        self._gateway_idx += 1
        return gw

    def compute_cid(self, content: bytes) -> str:
        """Настоящий CIDv1 (raw, sha2-256, base32) для одноблочного контента."""
        digest = hashlib.sha256(content).digest()
        cid_bytes = bytes([0x01, 0x55, 0x12, 0x20]) + digest
        return "b" + base64.b32encode(cid_bytes).decode("ascii").rstrip("=").lower()

    async def publish(self, name: str, content: bytes) -> str:
        """
        Публикует контент в IPFS.

        При заданном IPFS_API_URL блок добавляется на узел Kubo и запоминается
        CID, который вернул демон, — он реально доступен через gateway. Без узла
        CID только вычисляется и помечается unpinned: раздать его нельзя, пока
        оператор не запинит блок на своём узле.
        """
        if Config.IPFS_API_URL:
            cid = await self._add_to_node(content)
            if cid:
                self._published[name] = {"cid": cid, "pinned": True}
                logger.info("IPFS: pinned %s → %s", name, cid[:20])
                return cid
            logger.warning("IPFS: node add failed for %s, using offline CID", name)

        cid = self.compute_cid(content)
        self._published[name] = {"cid": cid, "pinned": False}
        logger.info("IPFS: unpinned CID for %s → %s", name, cid[:20])
        return cid

    async def _add_to_node(self, content: bytes) -> Optional[str]:
        try:
            import httpx

            files = {"file": ("blob", content, "application/octet-stream")}
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    Config.IPFS_API_URL.rstrip("/") + "/api/v0/add",
                    params={"cid-version": "1", "raw-leaves": "true", "pin": "true"},
                    files=files,
                )
                if resp.status_code == 200:
                    return resp.json().get("Hash")
                logger.warning("IPFS node add returned %s", resp.status_code)
        except Exception as e:
            logger.debug("IPFS node add error: %s", e)
        return None

    def get_gateway_url(self, cid: str) -> str:
        """Возвращает URL для доступа через gateway."""
        return self._next_gateway() + cid

    def get_all_gateway_urls(self, cid: str) -> list[str]:
        """Все gateway URL для одного CID (failover)."""
        return [gw + cid for gw in self.GATEWAYS]

    def get_status(self) -> dict:
        pinned = {n: m["cid"][:20] + "..." for n, m in self._published.items() if m["pinned"]}
        unpinned = [n for n, m in self._published.items() if not m["pinned"]]
        return {
            "node_configured": bool(Config.IPFS_API_URL),
            "gateways": len(self.GATEWAYS),
            "pinned_items": len(pinned),
            "unpinned_items": len(unpinned),
            "pinned": pinned,
            "unpinned": unpinned,
        }


class DecentralizedDNS:
    """
    Домены вне контроля ICANN / РКН.

    Handshake (.hns) резолвится в реальный IP через публичный DoH-резолвер
    hnsdoh.com. ENS (.eth) A-записи не имеет — к содержимому обращаются через
    gateway eth.limo (добавить суффикс .eth.limo). Локально заданные записи
    имеют приоритет над сетью.
    """

    HNS_DOH_RESOLVER = "https://hnsdoh.com/dns-query"
    ENS_GATEWAY = "eth.limo"

    def __init__(self):
        self._domains: dict[str, dict] = {}

    def register_domain(self, domain: str, dns_type: str, records: dict):
        """
        Регистрирует домен в конфигурации.
        records: {"A": "1.2.3.4", "AAAA": "::1", "TXT": "..."}
        """
        self._domains[domain] = {"type": dns_type, "records": records}

    def content_url(self, domain: str) -> Optional[str]:
        """URL содержимого .eth-домена через gateway eth.limo."""
        if domain.endswith(".eth"):
            return f"https://{domain[:-4]}.{self.ENS_GATEWAY}"
        return None

    async def resolve(self, domain: str) -> Optional[str]:
        """
        Резолвит домен в IP-адрес: A-запись или None.
        У .eth A-записи нет — для содержимого используйте content_url().
        """
        if domain in self._domains:
            return self._domains[domain].get("records", {}).get("A")
        if domain.endswith(".hns"):
            return await self._resolve_hns(domain)
        return None

    async def _resolve_hns(self, domain: str) -> Optional[str]:
        query = self._build_dns_query(domain)
        dns_param = base64.urlsafe_b64encode(query).rstrip(b"=").decode("ascii")
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    self.HNS_DOH_RESOLVER,
                    params={"dns": dns_param},
                    headers={"accept": "application/dns-message"},
                )
                if resp.status_code == 200:
                    for ip in self._parse_a_records(resp.content):
                        return ip
        except Exception as e:
            logger.debug("Handshake DoH resolve error: %s", e)
        return None

    @staticmethod
    def _build_dns_query(domain: str) -> bytes:
        header = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for label in domain.rstrip(".").split("."):
            encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
            question += bytes([len(encoded)]) + encoded
        question += b"\x00\x00\x01\x00\x01"
        return header + question

    @staticmethod
    def _skip_name(wire: bytes, off: int) -> int:
        while off < len(wire):
            length = wire[off]
            if length == 0:
                return off + 1
            if length & 0xC0 == 0xC0:
                return off + 2
            off += 1 + length
        return off

    @classmethod
    def _parse_a_records(cls, wire: bytes) -> list[str]:
        if len(wire) < 12:
            return []
        ancount = int.from_bytes(wire[6:8], "big")
        off = cls._skip_name(wire, 12) + 4
        ips: list[str] = []
        for _ in range(ancount):
            off = cls._skip_name(wire, off)
            if off + 10 > len(wire):
                break
            rtype = int.from_bytes(wire[off : off + 2], "big")
            rdlength = int.from_bytes(wire[off + 8 : off + 10], "big")
            rdata = off + 10
            if rtype == 1 and rdlength == 4 and rdata + 4 <= len(wire):
                ips.append(".".join(str(b) for b in wire[rdata : rdata + 4]))
            off = rdata + rdlength
        return ips

    def get_status(self) -> dict:
        return {
            "registered_domains": len(self._domains),
            "hns_resolver": self.HNS_DOH_RESOLVER,
            "ens_gateway": self.ENS_GATEWAY,
        }


# 9. CENSORSHIP AUTO-PROBE


class CensorshipAutoProbe:
    """
    Автоматическое определение заблокированных транспортов.

    При запуске клиент проверяет:
    1. Direct HTTPS к серверу — работает?
    2. WebSocket upgrade — работает?
    3. SSE long-poll — работает?
    4. CDN relay — работает?
    5. Tor — работает?
    6. QUIC/UDP — работает?

    Результат: выбирает лучший работающий транспорт.
    """

    PROBES = [
        {"name": "reality", "priority": 1, "timeout": 8.0},
        {"name": "direct_https", "priority": 2, "timeout": 5.0},
        {"name": "websocket", "priority": 3, "timeout": 5.0},
        {"name": "sse", "priority": 4, "timeout": 8.0},
        {"name": "trojan", "priority": 5, "timeout": 10.0},
        {"name": "shadowtls", "priority": 6, "timeout": 10.0},
        {"name": "cdn_relay", "priority": 7, "timeout": 10.0},
        {"name": "meek_cdn", "priority": 8, "timeout": 15.0},
        {"name": "doh_tunnel", "priority": 9, "timeout": 15.0},
        {"name": "tor", "priority": 10, "timeout": 30.0},
    ]

    def __init__(self):
        self._results: dict[str, dict] = {}
        self._best_transport: Optional[str] = None
        self._last_probe_time: float = 0
        self._probe_base = 300.0
        self._probe_interval = _jittered_delay(self._probe_base)

    async def probe_all(self, server_url: str) -> dict[str, dict]:
        """
        Проверяет все транспорты параллельно.
        server_url: базовый URL сервера.
        """
        tasks = {}
        for probe in self.PROBES:
            tasks[probe["name"]] = asyncio.create_task(self._run_probe(probe, server_url))

        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await asyncio.wait_for(task, timeout=35.0)
            except asyncio.TimeoutError:
                results[name] = {"ok": False, "latency": -1, "error": "timeout"}

        self._results = results
        self._last_probe_time = time.time()
        self._probe_interval = _jittered_delay(self._probe_base)

        self._best_transport = self._select_best(results)
        logger.info("Censorship probe: best transport = %s", self._best_transport)

        return results

    async def _run_probe(self, probe: dict, server_url: str) -> dict:
        """Запускает один probe."""
        name = probe["name"]
        start = time.monotonic()

        try:
            if name == "direct_https":
                return await self._probe_https(server_url, probe["timeout"])
            elif name == "websocket":
                return await self._probe_websocket(server_url, probe["timeout"])
            elif name == "sse":
                return await self._probe_sse(server_url, probe["timeout"])
            elif name in ("reality", "cdn_relay", "meek_cdn", "doh_tunnel", "tor", "shadowtls", "trojan"):
                token = hashlib.sha256(name.encode()).hexdigest()[:12]
                return await self._probe_endpoint(server_url, f"/api/transport/probe/{token}", probe["timeout"])
            else:
                return {"ok": False, "latency": -1, "error": "unknown_probe"}
        except Exception as e:
            elapsed = time.monotonic() - start
            return {"ok": False, "latency": round(elapsed * 1000), "error": str(e)}

    async def _probe_https(self, url: str, timeout: float) -> dict:
        start = time.monotonic()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=timeout, verify=False) as c:  # noqa: S501
                resp = await c.get(f"{url}/api/health")
                elapsed = time.monotonic() - start
                return {
                    "ok": resp.status_code in (200, 401, 403),
                    "latency": round(elapsed * 1000),
                    "status": resp.status_code,
                }
        except Exception as e:
            return {"ok": False, "latency": -1, "error": str(e)}

    async def _probe_websocket(self, url: str, timeout: float) -> dict:
        start = time.monotonic()
        url.replace("https://", "wss://").replace("http://", "ws://")
        try:
            import httpx

            async with httpx.AsyncClient(timeout=timeout, verify=False) as c:  # noqa: S501
                # Проверяем что WS endpoint отвечает (даже 401 = доступен)
                resp = await c.get(f"{url}/ws/chat/0")
                elapsed = time.monotonic() - start
                return {
                    "ok": resp.status_code in (101, 200, 401, 403, 426),
                    "latency": round(elapsed * 1000),
                    "status": resp.status_code,
                }
        except Exception as e:
            return {"ok": False, "latency": -1, "error": str(e)}

    async def _probe_sse(self, url: str, timeout: float) -> dict:
        start = time.monotonic()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=3.0, verify=False) as c:  # noqa: S501
                resp = await c.get(f"{url}/api/transport/sse/stream", headers={"Accept": "text/event-stream"})
                elapsed = time.monotonic() - start
                return {
                    "ok": resp.status_code in (200, 401, 403),
                    "latency": round(elapsed * 1000),
                }
        except Exception as e:
            return {"ok": False, "latency": -1, "error": str(e)}

    async def _probe_endpoint(self, url: str, path: str, timeout: float) -> dict:
        start = time.monotonic()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=timeout, verify=False) as c:  # noqa: S501
                resp = await c.get(f"{url}{path}")
                elapsed = time.monotonic() - start
                return {
                    "ok": resp.status_code in (200, 401, 403, 404, 501),
                    "latency": round(elapsed * 1000),
                    "status": resp.status_code,
                }
        except Exception as e:
            return {"ok": False, "latency": -1, "error": str(e)}

    def _select_best(self, results: dict) -> Optional[str]:
        """Выбирает лучший работающий транспорт по приоритету."""
        for probe in self.PROBES:
            name = probe["name"]
            if name in results and results[name].get("ok"):
                return name
        return None

    @property
    def best_transport(self) -> Optional[str]:
        return self._best_transport

    def needs_reprobe(self) -> bool:
        return (time.time() - self._last_probe_time) > self._probe_interval

    def get_status(self) -> dict:
        return {
            "best_transport": self._best_transport,
            "last_probe": self._last_probe_time,
            "results": self._results,
        }


# 10. CDN WORKERS PROXY (Store-and-Forward)


class CDNWorkersProxy:
    """
    Cloudflare Workers KV как store-and-forward прокси.

    Workers хранит сообщения в KV store:
    - Отправитель POST → Worker → KV put
    - Получатель GET → Worker → KV get → delete

    Даже если сервер Vortex полностью заблокирован — Workers KV работает.
    Блокировка Cloudflare = блокировка 20% интернета.
    """

    WORKER_TEMPLATE = """\
// Cloudflare Worker — Vortex Store-and-Forward Proxy
// Использует Workers KV для хранения сообщений
//
// Привязать KV namespace: VORTEX_KV

const AUTH_SECRET = "{secret}";
const AUTH_SECRET_PREV = "{prev_secret}";
const BACKEND = "{backend_url}";
const MSG_TTL = 3600; // 1 час TTL для сообщений в KV

export default {{
  async fetch(request, env) {{
    const url = new URL(request.url);

    const sid = readCookie(request.headers.get("Cookie"), "sid");
    const dot = sid.indexOf(".");
    const ts = dot < 0 ? "" : sid.slice(0, dot);
    const auth = dot < 0 ? "" : sid.slice(dot + 1);
    if (!(await authorized(auth, ts))) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    if (url.pathname === "/api/1/objects" && request.method === "POST") {{
      const body = await request.json();
      const key = `msg:${{body.to}}:${{Date.now()}}:${{crypto.randomUUID()}}`;
      await env.VORTEX_KV.put(key, JSON.stringify(body.data), {{
        expirationTtl: MSG_TTL,
      }});
      return new Response(JSON.stringify({{ ok: true, key }}), {{
        headers: {{ "Content-Type": "application/json" }},
      }});
    }}

    if (url.pathname === "/api/1/objects" && request.method === "GET") {{
      const user = url.searchParams.get("user") || "";
      const prefix = `msg:${{user}}:`;
      const list = await env.VORTEX_KV.list({{ prefix }});
      const messages = [];
      for (const key of list.keys) {{
        const val = await env.VORTEX_KV.get(key.name);
        if (val) {{
          messages.push(JSON.parse(val));
          await env.VORTEX_KV.delete(key.name);
        }}
      }}
      return new Response(JSON.stringify({{ messages }}), {{
        headers: {{ "Content-Type": "application/json" }},
      }});
    }}

    const backendUrl = new URL(url.pathname + url.search, BACKEND);
    const proxyReq = new Request(backendUrl, {{
      method: request.method,
      headers: request.headers,
      body: request.body,
    }});
    return fetch(proxyReq);
  }},
}};

function readCookie(header, name) {{
  for (const part of (header || "").split(";")) {{
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }}
  return "";
}}

async function authorized(auth, ts) {{
  for (const secret of [AUTH_SECRET, AUTH_SECRET_PREV]) {{
    if (secret && auth === await hmacSign(secret, ts)) return true;
  }}
  return false;
}}

async function hmacSign(secret, message) {{
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), {{ name: "HMAC", hash: "SHA-256" }}, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}}
"""

    def __init__(self, worker_url: str = "", secret: str = ""):
        self.worker_url = worker_url or os.environ.get("CDN_WORKER_KV_URL", "")
        self._explicit_secret = secret
        self.reload_secrets()

    def reload_secrets(self) -> None:
        """Перечитывает секрет из конфигурации (вызывается после ротации)."""
        self._secret = self._explicit_secret or Config.CDN_WORKER_KV_SECRET
        self._prev_secret = "" if self._explicit_secret else previous("CDN_WORKER_KV_SECRET")

    def generate_worker_script(self, backend_url: str = "http://127.0.0.1:8000") -> str:
        """Генерирует Worker скрипт для деплоя."""
        return self.WORKER_TEMPLATE.format(
            secret=self._secret,
            prev_secret=self._prev_secret,
            backend_url=backend_url,
        )

    def get_auth_headers(self) -> dict:
        """Генерирует заголовки авторизации для запроса к Worker."""
        ts = str(int(time.time()))
        sig = hmac.new(self._secret.encode(), ts.encode(), hashlib.sha256).hexdigest()
        return {"Cookie": f"sid={ts}.{sig}"}

    async def send_message(self, to_user: str, data: dict) -> bool:
        """Отправляет сообщение через Workers KV."""
        if not self.worker_url:
            return False
        try:
            import httpx

            headers = self.get_auth_headers()
            headers["Content-Type"] = "application/json"
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.post(
                    f"{self.worker_url}/api/1/objects",
                    json={"to": to_user, "data": data},
                    headers=headers,
                )
                return resp.status_code == 200
        except Exception as e:
            logger.debug("CDN Worker KV send error: %s", e)
            return False

    async def recv_messages(self, user_id: str) -> list[dict]:
        """Получает сообщения из Workers KV."""
        if not self.worker_url:
            return []
        try:
            import httpx

            headers = self.get_auth_headers()
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(
                    f"{self.worker_url}/api/1/objects",
                    params={"user": user_id},
                    headers=headers,
                )
                if resp.status_code == 200:
                    return resp.json().get("messages", [])
        except Exception as e:
            logger.debug("CDN Worker KV recv error: %s", e)
        return []

    def get_status(self) -> dict:
        return {
            "enabled": bool(self.worker_url),
            "worker_url": self.worker_url[:30] + "..." if self.worker_url else None,
        }


# 10b. AWS LAMBDA@EDGE RELAY (Store-and-Forward via CloudFront)


class AWSLambdaRelay:
    """
    AWS Lambda@Edge + CloudFront store-and-forward relay.

    Архитектура:
    - Lambda@Edge обрабатывает запросы на уровне CloudFront CDN
    - DynamoDB (или S3) хранит сообщения с TTL
    - Авторизация через CloudFront signed URLs (RSA-SHA1)

    Преимущества:
    - CloudFront — глобальная CDN, блокировка = блокировка AWS
    - Lambda@Edge работает на edge-локациях (низкая задержка)
    - Signed URLs не позволяют неавторизованным читать/писать
    """

    LAMBDA_TEMPLATE = """\
// AWS Lambda@Edge — Vortex Store-and-Forward
// Trigger: CloudFront viewer-request
// DynamoDB table: VortexMessages (partition key: recipient, sort key: msg_id)

const AWS = require('aws-sdk');
const crypto = require('crypto');

const AUTH_SECRET = "{secret}";
const AUTH_SECRET_PREV = "{prev_secret}";
const TABLE_NAME = "VortexMessages";
const MSG_TTL_SECONDS = 3600;

const dynamo = new AWS.DynamoDB.DocumentClient({{ region: "{region}" }});

exports.handler = async (event) => {{
    const request = event.Records[0].cf.request;
    const uri = request.uri;
    const method = request.method;

    const qs = request.querystring || "";
    if (!verifySignature(uri, qs)) {{
        return {{ status: "403", body: "Forbidden" }};
    }}

    if (uri === "/api/1/objects" && method === "POST") {{
        const body = JSON.parse(Buffer.from(request.body.data, "base64").toString());
        const item = {{
            recipient: body.to,
            msg_id: `${{Date.now()}}:${{crypto.randomUUID()}}`,
            data: JSON.stringify(body.data),
            ttl: Math.floor(Date.now() / 1000) + MSG_TTL_SECONDS,
        }};
        await dynamo.put({{ TableName: TABLE_NAME, Item: item }}).promise();
        return {{
            status: "200",
            body: JSON.stringify({{ ok: true, id: item.msg_id }}),
            headers: {{ "content-type": [{{ value: "application/json" }}] }},
        }};
    }}

    if (uri === "/api/1/objects" && method === "GET") {{
        const params = new URLSearchParams(qs);
        const user = params.get("user") || "";
        const result = await dynamo.query({{
            TableName: TABLE_NAME,
            KeyConditionExpression: "recipient = :r",
            ExpressionAttributeValues: {{ ":r": user }},
        }}).promise();

        const messages = [];
        for (const item of (result.Items || [])) {{
            messages.push(JSON.parse(item.data));
            await dynamo.delete({{
                TableName: TABLE_NAME,
                Key: {{ recipient: item.recipient, msg_id: item.msg_id }},
            }}).promise();
        }}
        return {{
            status: "200",
            body: JSON.stringify({{ messages }}),
            headers: {{ "content-type": [{{ value: "application/json" }}] }},
        }};
    }}

    return request;
}};

function verifySignature(uri, qs) {{
    const params = new URLSearchParams(qs);
    const sig = params.get("Signature") || "";
    const expires = params.get("Expires") || "";
    if (!sig || !expires) return false;
    if (Math.floor(Date.now() / 1000) > Number(expires)) return false;
    return [AUTH_SECRET, AUTH_SECRET_PREV].some(
        secret => secret && signatureMatches(sig, uri + expires, secret));
}}

function signatureMatches(sig, message, secret) {{
    const expected = crypto.createHmac("sha256", secret)
        .update(message).digest("hex");
    const given = Buffer.from(sig, "hex");
    const want = Buffer.from(expected, "hex");
    if (given.length !== want.length) return false;
    return crypto.timingSafeEqual(given, want);
}}
"""

    SIGNED_URL_TTL = 300
    KEY_PAIR_ID = "APKAEIBAERJR2EXAMPLE"

    def __init__(self, cloudfront_domain: str = "", secret: str = "", region: str = "us-east-1"):
        self.cloudfront_domain = cloudfront_domain or os.environ.get("AWS_CLOUDFRONT_DOMAIN", "")
        self._explicit_secret = secret
        self._region = region
        self.reload_secrets()

    def reload_secrets(self) -> None:
        """Перечитывает секрет из конфигурации (вызывается после ротации)."""
        self._secret = self._explicit_secret or Config.AWS_RELAY_SECRET
        self._prev_secret = "" if self._explicit_secret else previous("AWS_RELAY_SECRET")

    def generate_lambda_script(self) -> str:
        """Генерирует Lambda@Edge скрипт для деплоя."""
        return self.LAMBDA_TEMPLATE.format(
            secret=self._secret,
            prev_secret=self._prev_secret,
            region=self._region,
        )

    def _sign_url(self, path: str, query: str = "") -> str:
        """Генерирует signed URL в стиле CloudFront (Expires/Signature/Key-Pair-Id)."""
        expires = str(int(time.time()) + self.SIGNED_URL_TTL)
        sig = hmac.new(self._secret.encode(), (path + expires).encode(), hashlib.sha256).hexdigest()
        parts = [f"Expires={expires}", f"Signature={sig}", f"Key-Pair-Id={self.KEY_PAIR_ID}"]
        if query:
            parts.insert(0, query)
        return f"https://{self.cloudfront_domain}{path}?{'&'.join(parts)}"

    async def send_message(self, to_user: str, data: dict) -> bool:
        """Отправляет сообщение через Lambda@Edge relay."""
        if not self.cloudfront_domain:
            return False
        url = self._sign_url("/api/1/objects")
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.post(url, json={"to": to_user, "data": data})
                return resp.status_code == 200
        except Exception as e:
            logger.debug("AWS Lambda relay send error: %s", e)
            return False

    async def recv_messages(self, user_id: str) -> list[dict]:
        """Получает сообщения из Lambda@Edge relay."""
        if not self.cloudfront_domain:
            return []
        url = self._sign_url("/api/1/objects", f"user={user_id}")
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(url)
                if resp.status_code == 200:
                    return resp.json().get("messages", [])
        except Exception as e:
            logger.debug("AWS Lambda relay recv error: %s", e)
        return []

    def get_status(self) -> dict:
        return {
            "enabled": bool(self.cloudfront_domain),
            "cloudfront_domain": self.cloudfront_domain or None,
            "region": self._region,
        }


# 10c. AZURE CDN RELAY (Azure Functions + Azure CDN + SAS tokens)


class AzureCDNRelay:
    """
    Azure Functions + Azure CDN store-and-forward relay.

    Архитектура:
    - Azure Functions обрабатывает запросы за Azure CDN
    - Azure Table Storage хранит сообщения с TTL
    - Авторизация через SAS (Shared Access Signature) tokens

    Преимущества:
    - Azure CDN — глобальная CDN Microsoft, блокировка = блокировка Azure
    - SAS tokens — временные, одноразовые, не раскрывают ключ
    - Azure Functions — serverless, масштабируется автоматически
    """

    FUNCTION_TEMPLATE = """\
// Azure Function — Vortex Store-and-Forward
// Trigger: HTTP (behind Azure CDN)
// Storage: Azure Table Storage (table: VortexMessages)

const {{ TableClient, AzureNamedKeyCredential }} = require("@azure/data-tables");
const crypto = require("crypto");

const AUTH_SECRET = "{secret}";
const AUTH_SECRET_PREV = "{prev_secret}";
const TABLE_NAME = "VortexMessages";
const MSG_TTL_SECONDS = 3600;

const credential = new AzureNamedKeyCredential("{storage_account}", "{storage_key}");
const tableClient = new TableClient(
    `https://${{"{storage_account}"}}.table.core.windows.net`,
    TABLE_NAME,
    credential
);

module.exports = async function (context, req) {{
    const method = req.method;

    const sasToken = req.query["sig"] || "";
    const sasExpiry = req.query["se"] || "";
    if (!verifySAS(sasToken, sasExpiry, "objects")) {{
        context.res = {{ status: 403, body: "Forbidden" }};
        return;
    }}

    if (method === "POST") {{
        const body = req.body;
        const entity = {{
            partitionKey: body.to,
            rowKey: `${{Date.now()}}:${{crypto.randomUUID()}}`,
            data: JSON.stringify(body.data),
            expiresAt: new Date(Date.now() + MSG_TTL_SECONDS * 1000).toISOString(),
        }};
        await tableClient.createEntity(entity);
        context.res = {{
            status: 200,
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ ok: true, id: entity.rowKey }}),
        }};
        return;
    }}

    if (method === "GET") {{
        const user = req.query["user"] || "";
        const entities = tableClient.listEntities({{
            queryOptions: {{ filter: `PartitionKey eq '${{user}}'` }},
        }});
        const messages = [];
        for await (const entity of entities) {{
            messages.push(JSON.parse(entity.data));
            await tableClient.deleteEntity(entity.partitionKey, entity.rowKey);
        }}
        context.res = {{
            status: 200,
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ messages }}),
        }};
        return;
    }}

    context.res = {{ status: 404, body: "Not Found" }};
}};

function verifySAS(sig, expiry, resource) {{
    if (!sig || !expiry) return false;
    const now = new Date();
    if (now > new Date(expiry)) return false;
    const stringToSign = resource + "\\n" + expiry;
    return [AUTH_SECRET, AUTH_SECRET_PREV].some(secret => {{
        if (!secret) return false;
        const expected = crypto.createHmac("sha256", secret)
            .update(stringToSign).digest("base64");
        return sig === expected;
    }});
}}
"""

    # SAS token validity (seconds)
    SAS_TOKEN_TTL = 300

    def __init__(self, cdn_endpoint: str = "", secret: str = "", storage_account: str = "", storage_key: str = ""):
        self.cdn_endpoint = cdn_endpoint or os.environ.get("AZURE_CDN_ENDPOINT", "")
        self._explicit_secret = secret
        self._storage_account = storage_account or Config.AZURE_STORAGE_ACCOUNT
        self._storage_key = storage_key or os.environ.get("AZURE_STORAGE_KEY", "")
        self.reload_secrets()

    def reload_secrets(self) -> None:
        """Перечитывает секрет из конфигурации (вызывается после ротации)."""
        self._secret = self._explicit_secret or Config.AZURE_RELAY_SECRET
        self._prev_secret = "" if self._explicit_secret else previous("AZURE_RELAY_SECRET")

    def generate_function_script(self) -> str:
        """Генерирует Azure Function скрипт для деплоя."""
        return self.FUNCTION_TEMPLATE.format(
            secret=self._secret,
            prev_secret=self._prev_secret,
            storage_account=self._storage_account,
            storage_key=self._storage_key,
        )

    def _generate_sas_token(self, resource: str) -> dict:
        """
        Генерирует SAS (Shared Access Signature) параметры.
        Возвращает dict с параметрами sig и se (expiry) для query string.
        """
        expiry = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() + self.SAS_TOKEN_TTL),
        )
        string_to_sign = resource + "\n" + expiry
        sig = base64.b64encode(
            hmac.new(self._secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()
        ).decode()
        return {"sig": sig, "se": expiry}

    def _build_url(self, extra_params: Optional[dict] = None) -> str:
        """Строит URL с SAS токеном для запроса к Azure CDN."""
        sas = self._generate_sas_token("objects")
        params = {**sas}
        if extra_params:
            params.update(extra_params)
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://{self.cdn_endpoint}/api/1/objects?{qs}"

    async def send_message(self, to_user: str, data: dict) -> bool:
        """Отправляет сообщение через Azure CDN relay."""
        if not self.cdn_endpoint:
            return False
        url = self._build_url()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.post(url, json={"to": to_user, "data": data})
                return resp.status_code == 200
        except Exception as e:
            logger.debug("Azure CDN relay send error: %s", e)
            return False

    async def recv_messages(self, user_id: str) -> list[dict]:
        """Получает сообщения из Azure CDN relay."""
        if not self.cdn_endpoint:
            return []
        url = self._build_url(extra_params={"user": user_id})
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(url)
                if resp.status_code == 200:
                    return resp.json().get("messages", [])
        except Exception as e:
            logger.debug("Azure CDN relay recv error: %s", e)
        return []

    def get_status(self) -> dict:
        return {
            "enabled": bool(self.cdn_endpoint),
            "cdn_endpoint": self.cdn_endpoint or None,
            "storage_account": self._storage_account or None,
        }


# 11. SERVICE WORKER PROXY (config/metadata)


class ServiceWorkerConfig:
    """
    Конфигурация для клиентского Service Worker proxy.

    SW перехватывает все fetch() запросы и:
    - Добавляет обфускацию (padding, header order, cookies)
    - Выбирает лучший транспорт (WS / SSE / CDN / Meek)
    - Кеширует критические ресурсы для оффлайн
    - Автоматически переключает при блокировке

    Сам SW код → static/js/sw-proxy.js (генерируется ниже).
    """

    def generate_sw_config(self, transports: list[str], cdn_url: str = "", meek_url: str = "") -> dict:
        """
        Генерирует конфигурацию для Service Worker.

        probe_interval — базовый интервал проб, probe_interval_min/max — границы,
        в которых SW обязан выбирать задержку каждой пробы случайно (memoryless),
        чтобы не выдавать строгую периодичность наблюдателю. Потребитель
        (sw-proxy.js) должен планировать по этим границам, а не по фиксированному
        probe_interval.

        padding.buckets — лестница целевых длин, покрывающая реальный разброс
        размеров веб-ответов. Потребитель обязан дополнять запрос до ближайшего
        бакета, который не меньше его длины, а с вероятностью
        padding.promote_probability — до следующего за ним, иначе длина чуть
        ниже границы остаётся отличимой от длины на границе. Всё, что длиннее
        верхнего бакета, дополняется до кратного padding.tile_step.

        Добавлять к длине случайную величину запрещено: аддитивный шум с узкой
        полосой не скрывает исходное распределение длин — наблюдатель разворачивает
        свёртку по гистограмме, — а сама полоса добавки становится приметой.
        Округление вверх до бакета, наоборот, склеивает целый диапазон длин в
        одно наблюдаемое значение.
        """
        return {
            "version": "4.0",
            "transports": transports,
            "primary_transport": transports[0] if transports else "direct",
            "cdn_relay_url": cdn_url,
            "meek_url": meek_url,
            "cache_ttl": 3600,
            "probe_interval": 60,
            "probe_interval_min": round(60 * _PROBE_JITTER_LOW),
            "probe_interval_max": round(60 * _PROBE_JITTER_HIGH),
            "padding": {
                "enabled": True,
                "buckets": list(_PAD_BUCKETS),
                "promote_probability": _PAD_PROMOTE_PROBABILITY,
                "tile_step": _PAD_TILE_STEP,
            },
            "retry": {
                "max_attempts": 3,
                "backoff_base": 1000,
                "backoff_max": 30000,
            },
        }

    @staticmethod
    def get_sw_registration_script() -> str:
        """JS код для регистрации Service Worker."""
        return """\
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/static/js/sw-proxy.js', {
        scope: '/',
        type: 'module',
    }).then(reg => {
        console.log('[SW] Registered:', reg.scope);
        // Передаём конфигурацию
        fetch('/api/transport/sw-config')
            .then(r => r.json())
            .then(config => {
                if (reg.active) {
                    reg.active.postMessage({type: 'config', config});
                }
            });
    }).catch(err => console.warn('[SW] Registration failed:', err));
}
"""


# 12. WASM CRYPTO MODULE


class WASMCryptoConfig:
    """
    Конфигурация WASM-криптографии для клиента.

    WebAssembly модуль с:
    - X25519 key exchange
    - AES-256-GCM encryption
    - Argon2id key derivation
    - BLAKE2b hashing
    - Double Ratchet (Signal protocol)

    Преимущества перед JS:
    - 5-10x быстрее
    - Сложнее реверсить (бинарный формат)
    - Constant-time operations (защита от timing attacks)
    """

    # Rust → WASM build конфигурация (Cargo.toml секция)
    CARGO_TOML_TEMPLATE = """\
[package]
name = "vortex-crypto"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
x25519-dalek = "2"
aes-gcm = "0.10"
argon2 = "0.5"
blake2 = "0.10"
rand = {{ version = "0.8", features = ["getrandom"] }}
getrandom = {{ version = "0.2", features = ["js"] }}

[profile.release]
opt-level = "z"
lto = true
strip = true
"""

    def generate_build_instructions(self) -> str:
        """Инструкции для сборки WASM модуля."""
        return """\
# Сборка WASM криптографического модуля:
# 1. Установить wasm-pack:
#    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
#
# 2. В директории crypto-wasm/:
#    wasm-pack build --target web --release
#
# 3. Скопировать pkg/ в static/wasm/
#    cp -r pkg/ ../../static/wasm/vortex-crypto/
#
# 4. Использование в JS:
#    import init, { encrypt, decrypt, keygen } from '/static/wasm/vortex-crypto/vortex_crypto.js';
#    await init();
#    const keys = keygen();
"""

    def get_loader_script(self) -> str:
        """JS код для загрузки WASM модуля."""
        return """\
let _wasmReady = false;
let _wasmModule = null;

async function initWasmCrypto() {
    try {
        const module = await import('/static/wasm/vortex-crypto/vortex_crypto.js');
        await module.default();
        _wasmModule = module;
        _wasmReady = true;
        console.log('[WASM] Crypto module loaded');
    } catch (e) {
        console.warn('[WASM] Not available, falling back to JS crypto:', e.message);
    }
}

function isWasmReady() { return _wasmReady; }
function getWasmModule() { return _wasmModule; }
"""

    def get_status(self) -> dict:
        return {
            "build_target": "wasm32-unknown-unknown",
            "algorithms": ["x25519", "aes-256-gcm", "argon2id", "blake2b"],
        }


# 13. OBLIVIOUS HTTP (OHTTP)


class ObliviousHTTP:
    """
    OHTTP (RFC 9458): relay скрывает IP клиента от сервера.

    Архитектура:
    Client → Relay (не видит содержимое) → Gateway (не видит IP) → Server

    Relay знает IP клиента, но не видит запрос (зашифрован для Gateway).
    Gateway видит запрос, но не знает IP (от Relay).

    Никто не видит обе части одновременно.

    Упрощённая реализация для Vortex:
    - Relay = любая Vortex-нода (или CDN Worker)
    - Gateway = целевая Vortex-нода
    - Шифрование: HPKE (Hybrid Public Key Encryption)
    """

    OHTTP_HEADER = struct.pack(">BHHH", 0x01, 0x0020, 0x0001, 0x0001)

    def __init__(self, gateway_public_key: bytes = b""):
        if gateway_public_key:
            self._gateway_private = None
            self._gateway_pubkey = gateway_public_key
        else:
            self._gateway_private = X25519PrivateKey.generate()
            self._gateway_pubkey = self._gateway_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._relay_urls: list[str] = []

    @property
    def gateway_public_key(self) -> bytes:
        return self._gateway_pubkey

    def add_relay(self, url: str):
        """Добавляет relay endpoint."""
        self._relay_urls.append(url)

    def _hpke_context(self, enc: bytes, shared: bytes) -> tuple[bytes, bytes]:
        okm = HKDF(
            algorithm=hashes.SHA256(),
            length=28,
            salt=self._gateway_pubkey,
            info=self.OHTTP_HEADER + enc + b"ohttp request",
        ).derive(shared)
        return okm[:16], okm[16:28]

    def _client_seal(self, request_data: bytes) -> tuple[bytes, bytes, bytes]:
        ephemeral = X25519PrivateKey.generate()
        enc = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(self._gateway_pubkey))
        key, nonce = self._hpke_context(enc, shared)
        ciphertext = AESGCM(key).encrypt(nonce, request_data, self.OHTTP_HEADER)
        return self.OHTTP_HEADER + enc + ciphertext, enc, shared

    def encapsulate_request(self, request_data: bytes) -> bytes:
        """
        Инкапсулирует запрос для gateway.

        HPKE (X25519 → HKDF-SHA256 → AES-128-GCM). Заголовок открыт (gateway
        выбирает по нему ключ), эфемерный публичный ключ передаётся открыто,
        тело шифруется на общем ECDH-секрете. Формат:
        [1B key_id][2B kem_id][2B kdf_id][2B aead_id]
        [32B enc (эфемерный публичный ключ)][AEAD ciphertext]
        """
        encapsulated, _enc, _shared = self._client_seal(request_data)
        return encapsulated

    def decapsulate_request(self, encapsulated: bytes) -> Optional[bytes]:
        """Декапсулирует запрос на gateway стороне (требуется приватный ключ)."""
        if self._gateway_private is None or len(encapsulated) < 55:
            return None
        if encapsulated[:7] != self.OHTTP_HEADER:
            return None
        enc = encapsulated[7:39]
        ciphertext = encapsulated[39:]
        try:
            shared = self._gateway_private.exchange(X25519PublicKey.from_public_bytes(enc))
            key, nonce = self._hpke_context(enc, shared)
            return AESGCM(key).decrypt(nonce, ciphertext, self.OHTTP_HEADER)
        except Exception:
            return None

    @staticmethod
    def _response_context(enc: bytes, shared: bytes, response_nonce: bytes) -> tuple[bytes, bytes]:
        okm = HKDF(
            algorithm=hashes.SHA256(),
            length=28,
            salt=enc + response_nonce,
            info=b"ohttp response",
        ).derive(shared)
        return okm[:16], okm[16:28]

    def seal_response(self, encapsulated: bytes, response_data: bytes) -> Optional[bytes]:
        """
        Шифрует ответ gateway для клиента (обратный путь OHTTP).

        Ключ ответа выводится из того же ECDH-секрета плюс свежий response_nonce,
        поэтому relay ответ прочитать не может. Формат: [16B response_nonce][ct].
        """
        if self._gateway_private is None or len(encapsulated) < 39:
            return None
        enc = encapsulated[7:39]
        try:
            shared = self._gateway_private.exchange(X25519PublicKey.from_public_bytes(enc))
        except Exception:
            return None
        response_nonce = os.urandom(16)
        key, nonce = self._response_context(enc, shared, response_nonce)
        ct = AESGCM(key).encrypt(nonce, response_data, b"ohttp response")
        return response_nonce + ct

    def open_response(self, enc: bytes, shared: bytes, enc_response: bytes) -> Optional[bytes]:
        """Расшифровывает ответ gateway на стороне клиента."""
        if len(enc_response) < 16 + 16:
            return None
        response_nonce = enc_response[:16]
        ct = enc_response[16:]
        key, nonce = self._response_context(enc, shared, response_nonce)
        try:
            return AESGCM(key).decrypt(nonce, ct, b"ohttp response")
        except Exception:
            return None

    async def send_via_relay(self, request_data: bytes, target_gateway: str = "") -> Optional[bytes]:
        """Отправляет запрос через случайный relay и расшифровывает ответ gateway."""
        if not self._relay_urls:
            return None

        relay_url = _sysrand.choice(self._relay_urls)
        encapsulated, enc, shared = self._client_seal(request_data)

        try:
            import httpx

            async with httpx.AsyncClient(timeout=15.0) as c:
                resp = await c.post(
                    f"{relay_url}/api/1/edge",
                    content=encapsulated,
                    headers={"Content-Type": "application/octet-stream"},
                )
                if resp.status_code == 200:
                    return self.open_response(enc, shared, resp.content)
        except Exception as e:
            logger.debug("OHTTP relay error: %s", e)
        return None

    def get_status(self) -> dict:
        return {
            "relays": len(self._relay_urls),
            "encryption": "HPKE(X25519, SHA-256, AES-128-GCM)",
        }


# 14. CENSORSHIP DASHBOARD


class CensorshipDashboard:
    """
    Панель мониторинга блокировок по регионам.

    Собирает данные от клиентов:
    - Какие транспорты работают/заблокированы
    - Задержки по регионам
    - Время обнаружения блокировки

    Данные хранятся в памяти (in-memory), обновляются push'ами от клиентов.
    """

    def __init__(self):
        self._reports: dict[str, list[dict]] = {}  # region → [reports]
        self._max_reports_per_region = 100
        self._blocked_transports: dict[str, set[str]] = {}  # region → {transport_names}

    def submit_report(self, region: str, report: dict):
        """
        Клиент отправляет отчёт о доступности.
        report: {transports: {name: {ok, latency}}, timestamp, client_id}
        """
        if region not in self._reports:
            self._reports[region] = []
            self._blocked_transports[region] = set()

        self._reports[region].append(
            {
                **report,
                "received_at": time.time(),
            }
        )

        # Trim old reports
        if len(self._reports[region]) > self._max_reports_per_region:
            self._reports[region] = self._reports[region][-self._max_reports_per_region :]

        # Update blocked transports
        transports = report.get("transports", {})
        for name, result in transports.items():
            if not result.get("ok"):
                self._blocked_transports[region].add(name)
            else:
                self._blocked_transports[region].discard(name)

    def get_region_status(self, region: str) -> dict:
        """Статус блокировок для региона."""
        reports = self._reports.get(region, [])
        blocked = self._blocked_transports.get(region, set())

        return {
            "region": region,
            "total_reports": len(reports),
            "blocked_transports": sorted(blocked),
            "last_report": reports[-1] if reports else None,
        }

    def get_all_regions(self) -> dict:
        """Статус всех регионов."""
        result = {}
        for region in self._reports:
            result[region] = self.get_region_status(region)
        return result

    def get_recommended_transport(self, region: str) -> Optional[str]:
        """Рекомендованный транспорт для региона."""
        blocked = self._blocked_transports.get(region, set())
        all_transports = [
            "direct_https",
            "websocket",
            "sse",
            "reality",
            "trojan",
            "shadowtls",
            "cdn_relay",
            "meek_cdn",
            "doh_tunnel",
            "tor",
        ]
        for t in all_transports:
            if t not in blocked:
                return t
        return "tor"  # Tor as last resort

    def get_status(self) -> dict:
        return {
            "regions_monitored": len(self._reports),
            "regions": self.get_all_regions(),
        }


# 15. LATENCY PROBES


class LatencyProbeSystem:
    """
    Периодические пинги через все транспорты.

    Обнаруживает деградацию или блокировку ДО того,
    как пользователь заметит проблему.

    Пробы идут с memoryless-джиттером вокруг probe_interval (по умолчанию
    ~60 сек), а не строго периодически, чтобы наблюдатель не читал частоту.
    При обнаружении блокировки — автоматическое переключение.
    """

    def __init__(self, probe_interval: float = 60.0):
        self.probe_interval = probe_interval
        self._latencies: dict[str, list[float]] = {}
        self._max_history = 60
        self._alerts: list[dict] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._callback: Optional[Callable] = None

    async def start(
        self,
        probe_fn: Callable[[str], Awaitable[float]],
        transports: list[str],
        on_block: Optional[Callable[[str], Awaitable[None]]] = None,
    ):
        """
        Запуск системы мониторинга.
        probe_fn: async (transport_name) → latency_ms (-1 = failed)
        on_block: callback при обнаружении блокировки.
        """
        self._running = True
        self._callback = on_block
        self._task = asyncio.create_task(self._probe_loop(probe_fn, transports))

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    async def _probe_loop(self, probe_fn, transports: list[str]):
        while self._running:
            for transport in transports:
                try:
                    latency = await probe_fn(transport)

                    if transport not in self._latencies:
                        self._latencies[transport] = []

                    self._latencies[transport].append(latency)
                    if len(self._latencies[transport]) > self._max_history:
                        self._latencies[transport] = self._latencies[transport][-self._max_history :]

                    recent = self._latencies[transport][-3:]
                    if len(recent) >= 3 and all(lat < 0 for lat in recent):
                        alert = {
                            "transport": transport,
                            "type": "blocked",
                            "timestamp": time.time(),
                        }
                        self._alerts.append(alert)
                        logger.warning("Transport %s appears BLOCKED (3 consecutive failures)", transport)

                        if self._callback:
                            with contextlib.suppress(Exception):
                                await self._callback(transport)

                    elif latency > 0 and len(self._latencies[transport]) > 5:
                        avg = sum(lat for lat in self._latencies[transport][:-1] if lat > 0) / max(
                            1, sum(1 for lat in self._latencies[transport][:-1] if lat > 0)
                        )
                        if avg > 0 and latency > avg * 3:
                            self._alerts.append(
                                {
                                    "transport": transport,
                                    "type": "degraded",
                                    "latency": latency,
                                    "average": round(avg),
                                    "timestamp": time.time(),
                                }
                            )

                except asyncio.CancelledError:
                    return
                except Exception as e:
                    logger.debug("Latency probe error (%s): %s", transport, e)

            await asyncio.sleep(_jittered_delay(self.probe_interval, low=_PROBE_JITTER_LOW, high=_PROBE_JITTER_HIGH))

    def get_latency_stats(self) -> dict:
        """Статистика задержек по транспортам."""
        stats = {}
        for transport, history in self._latencies.items():
            valid = [lat for lat in history if lat > 0]
            stats[transport] = {
                "current": history[-1] if history else -1,
                "avg": round(sum(valid) / max(1, len(valid))) if valid else -1,
                "min": round(min(valid)) if valid else -1,
                "max": round(max(valid)) if valid else -1,
                "failures": sum(1 for lat in history if lat < 0),
                "total_probes": len(history),
            }
        return stats

    def get_recent_alerts(self, limit: int = 20) -> list[dict]:
        return self._alerts[-limit:]

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "probe_interval": self.probe_interval,
            "transports_monitored": len(self._latencies),
            "latencies": self.get_latency_stats(),
            "recent_alerts": self.get_recent_alerts(5),
        }


# MANAGER — Level 4


class StealthLevel4Manager:
    """
    Менеджер Level 4: боевые протоколы, инфраструктура, мониторинг.
    15 механизмов.
    """

    def __init__(self):
        # A. Боевые протоколы
        self.reality = RealityProtocol()
        self.shadowtls = ShadowTLS()
        self.trojan = TrojanProtocol()
        self.naiveproxy = NaiveProxyConfig()

        # B. Инфраструктура
        self.tor_hs = TorHiddenService()
        self.ipfs = IPFSDistributor()
        self.decentralized_dns = DecentralizedDNS()
        self.censor_probe = CensorshipAutoProbe()
        self.cdn_workers = CDNWorkersProxy()
        self.aws_lambda_relay = AWSLambdaRelay()
        self.azure_cdn_relay = AzureCDNRelay()

        # C. Клиент
        self.sw_config = ServiceWorkerConfig()
        self.wasm_crypto = WASMCryptoConfig()
        self.ohttp = ObliviousHTTP()

        # D. Мониторинг
        self.dashboard = CensorshipDashboard()
        self.latency_probes = LatencyProbeSystem()

        self._running = False

    def reload_secrets(self) -> None:
        """Перечитывает секреты во всех механизмах после плановой ротации."""
        for component in (
            self.shadowtls,
            self.trojan,
            self.naiveproxy,
            self.cdn_workers,
            self.aws_lambda_relay,
            self.azure_cdn_relay,
        ):
            component.reload_secrets()

    @staticmethod
    def _deploy_status() -> dict:
        from app.transport.relay_deploy import deploy_status

        return deploy_status()

    def get_client_secrets(self) -> dict:
        """
        Протокольные пароли для клиента: действующие и предыдущие (валидные до
        следующей ротации) плюс её время, чтобы клиент успел обновиться сам.

        Секреты релеев сюда не входят: к CDN Worker / Lambda / Azure Function
        ходит сервер, клиенту их знать незачем.
        """
        return {
            "shadowtls": {
                "password": Config.SHADOWTLS_PASSWORD,
                "previous_password": previous("SHADOWTLS_PASSWORD") or None,
            },
            "trojan": {
                "password": Config.TROJAN_PASSWORD,
                "previous_password": previous("TROJAN_PASSWORD") or None,
            },
            "naiveproxy": {
                "username": self.naiveproxy._username,
                "password": self.naiveproxy._password,
                "probe_domain": self.naiveproxy._probe_domain,
                "previous_username": previous("NAIVE_USERNAME") or None,
                "previous_password": previous("NAIVE_PASSWORD") or None,
                "previous_probe_domain": previous("NAIVE_PROBE_DOMAIN") or None,
            },
            "next_rotation": rotation_status().get("next_rotation"),
        }

    async def start(self):
        """Запуск Level 4."""
        self._running = True

        logger.info(
            "Stealth Level 4: started — "
            "reality=%s (flagship), shadowtls=%s, trojan=%s, naiveproxy=%s, "
            "tor=%s, ipfs=%s, ddns=%s, censor_probe=%s, cdn_kv=%s, "
            "sw=%s, wasm=%s, ohttp=%s, dashboard=%s, probes=%s",
            "ON",
            "ON",
            "ON",
            "config_ready",
            self.tor_hs.onion_address or "ready",
            "ON",
            "ON",
            "ON",
            "ON" if self.cdn_workers.worker_url else "config_needed",
            "ON",
            "ready",
            "ON",
            "ON",
            "ON",
        )

    def stop(self):
        self._running = False
        self.latency_probes.stop()

    def get_status(self) -> dict:
        return {
            # A. Protocols
            "reality": self.reality.get_status(),
            "shadowtls": self.shadowtls.get_status(),
            "trojan": self.trojan.get_status(),
            "naiveproxy": self.naiveproxy.get_status(),
            # B. Infrastructure
            "tor_hidden_service": self.tor_hs.get_status(),
            "ipfs": self.ipfs.get_status(),
            "decentralized_dns": self.decentralized_dns.get_status(),
            "censorship_auto_probe": self.censor_probe.get_status(),
            "cdn_workers_kv": self.cdn_workers.get_status(),
            "aws_lambda_relay": self.aws_lambda_relay.get_status(),
            "azure_cdn_relay": self.azure_cdn_relay.get_status(),
            "relay_deploy": self._deploy_status(),
            # C. Client
            "service_worker": True,
            "wasm_crypto": self.wasm_crypto.get_status(),
            "oblivious_http": self.ohttp.get_status(),
            # D. Monitoring
            "censorship_dashboard": self.dashboard.get_status(),
            "latency_probes": self.latency_probes.get_status(),
        }


# Global instance
stealth_l4 = StealthLevel4Manager()
register_reload_hook(stealth_l4.reload_secrets)
