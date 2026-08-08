"""Независимая Python-реализация формата ShadowTLS v2 (привязка к ServerRandom).

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная реализация формата, против которой сверяется `vortex-transport`.

    ключ пароля     = HKDF-SHA256(ikm = пароль, salt = нет, "shadowtls-password-v2", 32)
    salt расписания = random донора (32) ‖ session_id (16)
    switch-запись   = 0x17 0x03 0x03 ‖ len ‖ session_id(16) ‖ token(8) ‖ паддинг
    token           = HKDF-SHA256(ikm = ключ пароля, salt = salt, "shadowtls switch v2", 8)
    ключ c2s / s2c  = HKDF-SHA256(ikm = ключ пароля, salt = salt, "shadowtls c2s|s2c v2", 32)
    запись данных   = 0x17 0x03 0x03 ‖ len ‖ AES-256-GCM(данные), nonce = счётчик записи,
                      AAD = заголовок(5) ‖ счётчик u64 BE

Токен и ключи выводятся из random донора, поэтому перехваченная switch-запись не
проигрывается на другом соединении, а повтор session_id клиентом не повторяет
пару (ключ, nonce).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PASSWORD_INFO = b"shadowtls-password-v2"
SWITCH_INFO = b"shadowtls switch v2"
INFO_C2S = b"shadowtls c2s v2"
INFO_S2C = b"shadowtls s2c v2"

PASSWORD_KEY_LEN = 32
SESSION_KEY_LEN = 32
SWITCH_TOKEN_LEN = 8
SESSION_ID_LEN = 16
SERVER_RANDOM_LEN = 32
SWITCH_PREFIX_LEN = SESSION_ID_LEN + SWITCH_TOKEN_LEN

RECORD_HEADER_LEN = 5
MAX_RECORD_PAYLOAD = 16640
TLS_RECORD_MAX = 16384
TAG_LEN = 16
NONCE_LEN = 12
CONTENT_TYPES = (0x14, 0x15, 0x16, 0x17)
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17
EXTENSION_SERVER_NAME = 0x0000
MAX_HOST_LEN = 253


def password_key(password: bytes) -> Optional[bytes]:
    if not password:
        return None
    return HKDF(algorithm=hashes.SHA256(), length=PASSWORD_KEY_LEN, salt=None, info=PASSWORD_INFO).derive(password)


def schedule_salt(server_random: bytes, session_id: bytes) -> bytes:
    if len(server_random) != SERVER_RANDOM_LEN or len(session_id) != SESSION_ID_LEN:
        raise ValueError("random донора — 32 байта, session_id — 16 байт")
    return server_random + session_id


def expand(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


def switch_token(key: bytes, server_random: bytes, session_id: bytes) -> bytes:
    return expand(key, schedule_salt(server_random, session_id), SWITCH_INFO, SWITCH_TOKEN_LEN)


def session_keys(key: bytes, server_random: bytes, session_id: bytes) -> tuple[bytes, bytes]:
    salt = schedule_salt(server_random, session_id)
    return (
        expand(key, salt, INFO_C2S, SESSION_KEY_LEN),
        expand(key, salt, INFO_S2C, SESSION_KEY_LEN),
    )


def record(content_type: int, payload: bytes) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + len(payload).to_bytes(2, "big") + payload


def switch_record(password: bytes, server_random: bytes, session_id: bytes, padding: bytes = b"") -> bytes:
    key = password_key(password)
    if key is None:
        raise ValueError("пароль ShadowTLS не задан")
    body = session_id + switch_token(key, server_random, session_id) + padding
    return record(CONTENT_APPLICATION_DATA, body)


def match_switch_record(
    passwords: list[bytes], server_random: Optional[bytes], content_type: int, payload: bytes
) -> Optional[bytes]:
    if content_type != CONTENT_APPLICATION_DATA or len(payload) < SWITCH_PREFIX_LEN:
        return None
    if server_random is None:
        return None
    session_id = payload[:SESSION_ID_LEN]
    candidate = payload[SESSION_ID_LEN:SWITCH_PREFIX_LEN]
    for password in passwords:
        key = password_key(password)
        if key is None:
            continue
        if switch_token(key, server_random, session_id) == candidate:
            return session_id
    return None


class SealedStream:
    """Поток данных после переключения: AEAD поверх TLS-записей."""

    def __init__(self, key_send: bytes, key_recv: bytes):
        self._send = AESGCM(key_send)
        self._recv = AESGCM(key_recv)
        self._send_seq = 0
        self._recv_seq = 0

    @staticmethod
    def for_role(password: bytes, server_random: bytes, session_id: bytes, server: bool) -> SealedStream:
        key = password_key(password)
        if key is None:
            raise ValueError("пароль ShadowTLS не задан")
        c2s, s2c = session_keys(key, server_random, session_id)
        if server:
            return SealedStream(s2c, c2s)
        return SealedStream(c2s, s2c)

    @staticmethod
    def _nonce(seq: int) -> bytes:
        return bytes(NONCE_LEN - 8) + seq.to_bytes(8, "big")

    @staticmethod
    def _aad(header: bytes, seq: int) -> bytes:
        return header + seq.to_bytes(8, "big")

    def wrap(self, data: bytes) -> bytes:
        chunk = TLS_RECORD_MAX - TAG_LEN
        out = bytearray()
        offset = 0
        while True:
            piece = data[offset : offset + chunk]
            header = bytes([CONTENT_APPLICATION_DATA, 0x03, 0x03]) + (len(piece) + TAG_LEN).to_bytes(2, "big")
            out += header + self._send.encrypt(self._nonce(self._send_seq), piece, self._aad(header, self._send_seq))
            self._send_seq += 1
            offset += len(piece)
            if offset >= len(data):
                return bytes(out)

    def unwrap(self, frame: bytes) -> Optional[bytes]:
        out = bytearray()
        pos = 0
        while pos + RECORD_HEADER_LEN <= len(frame):
            header = frame[pos : pos + RECORD_HEADER_LEN]
            if header[0] != CONTENT_APPLICATION_DATA or header[1:3] != b"\x03\x03":
                return None
            body_len = int.from_bytes(header[3:5], "big")
            pos += RECORD_HEADER_LEN
            if pos + body_len > len(frame) or body_len < TAG_LEN:
                return None
            try:
                out += self._recv.decrypt(
                    self._nonce(self._recv_seq), frame[pos : pos + body_len], self._aad(header, self._recv_seq)
                )
            except Exception:
                return None
            self._recv_seq += 1
            pos += body_len
        if pos != len(frame):
            return None
        return bytes(out)


def split_records(data: bytes) -> tuple[list[bytes], bytes, bool]:
    """Разбор потока на целые TLS-записи: (записи, остаток, поток-не-TLS)."""
    records: list[bytes] = []
    pos = 0
    while True:
        if len(data) - pos < RECORD_HEADER_LEN:
            return records, data[pos:], False
        header = data[pos : pos + RECORD_HEADER_LEN]
        length = int.from_bytes(header[3:5], "big")
        if header[0] not in CONTENT_TYPES or header[1] != 0x03 or length > MAX_RECORD_PAYLOAD:
            return records, data[pos:], True
        if len(data) - pos < RECORD_HEADER_LEN + length:
            return records, data[pos:], False
        records.append(data[pos : pos + RECORD_HEADER_LEN + length])
        pos += RECORD_HEADER_LEN + length


def _strip_record(data: bytes) -> bytes:
    if data[:1] == bytes([CONTENT_HANDSHAKE]):
        return data[RECORD_HEADER_LEN:]
    return data


def server_random_of(data: bytes) -> Optional[bytes]:
    body = _strip_record(data)
    if body[:1] != b"\x02":
        return None
    random = body[6 : 6 + SERVER_RANDOM_LEN]
    if len(random) != SERVER_RANDOM_LEN:
        return None
    return random


def _client_hello_extensions(data: bytes) -> Optional[bytes]:
    body = _strip_record(data)
    if len(body) < 4 or body[0] != 0x01:
        return None
    pos = 4 + 2 + 32
    if pos + 1 > len(body):
        return None
    pos += 1 + body[pos]
    if pos + 2 > len(body):
        return None
    pos += 2 + int.from_bytes(body[pos : pos + 2], "big")
    if pos + 1 > len(body):
        return None
    pos += 1 + body[pos]
    if pos + 2 > len(body):
        return None
    end = min(len(body), pos + 2 + int.from_bytes(body[pos : pos + 2], "big"))
    return body[pos + 2 : end]


def _plausible_host(name: bytes) -> Optional[str]:
    if not name or len(name) > MAX_HOST_LEN:
        return None
    if not all(chr(b).isascii() and (chr(b).isalnum() or chr(b) in "-.") for b in name):
        return None
    return name.decode("ascii")


def server_name_of(data: bytes) -> Optional[str]:
    extensions = _client_hello_extensions(data)
    if extensions is None:
        return None
    pos = 0
    while pos + 4 <= len(extensions):
        kind = int.from_bytes(extensions[pos : pos + 2], "big")
        length = int.from_bytes(extensions[pos + 2 : pos + 4], "big")
        body = extensions[pos + 4 : pos + 4 + length]
        pos += 4 + length
        if kind != EXTENSION_SERVER_NAME:
            continue
        list_len = int.from_bytes(body[0:2], "big")
        end = min(len(body), 2 + list_len)
        entry = 2
        while entry + 3 <= end:
            name_len = int.from_bytes(body[entry + 1 : entry + 3], "big")
            name = body[entry + 3 : entry + 3 + name_len]
            is_host = body[entry] == 0x00
            entry += 3 + name_len
            if not is_host or len(name) != name_len:
                continue
            host = _plausible_host(name)
            if host is not None:
                return host
        return None
    return None


def build_client_hello(session_id: bytes, extensions: bytes) -> bytes:
    body = (
        b"\x03\x03"
        + bytes(32)
        + bytes([len(session_id)])
        + session_id
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def build_server_name_extension(host: bytes) -> bytes:
    entry = b"\x00" + len(host).to_bytes(2, "big") + host
    body = len(entry).to_bytes(2, "big") + entry
    return EXTENSION_SERVER_NAME.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def build_server_hello(server_random: bytes) -> bytes:
    body = b"\x03\x03" + server_random + b"\x20" + bytes(32) + b"\x13\x01" + b"\x00" + b"\x00\x00"
    return b"\x02" + len(body).to_bytes(3, "big") + body


def wrap_handshake(handshake: bytes) -> bytes:
    return record(CONTENT_HANDSHAKE, handshake)


PASSWORD = b"testpass"
PREVIOUS_PASSWORD = b"oldpass"
SERVER_RANDOM = bytes(range(32))
SESSION_ID = bytes(range(16))

_HELLO_WITH_SNI = build_client_hello(bytes(32), build_server_name_extension(b"www.google.com"))
_HELLO_WITHOUT_SNI = build_client_hello(bytes(32), b"")
_HELLO_UPPERCASE_SNI = build_client_hello(bytes(32), build_server_name_extension(b"WWW.APPLE.COM"))
_HELLO_BAD_SNI = build_client_hello(bytes(32), build_server_name_extension("гугл.рф".encode()))
_HELLO_EMPTY_SNI = build_client_hello(bytes(32), build_server_name_extension(b""))


def _switch_record_case(args: dict) -> dict:
    return {
        "record": switch_record(
            args["password"].encode(),
            bytes.fromhex(args["server_random"]),
            bytes.fromhex(args["session_id"]),
            bytes.fromhex(args["padding"]),
        ).hex()
    }


def _switch_token_case(args: dict) -> dict:
    key = password_key(args["password"].encode())
    return {
        "token": switch_token(key, bytes.fromhex(args["server_random"]), bytes.fromhex(args["session_id"])).hex()
    }


def _wrap_case(args: dict) -> dict:
    stream = SealedStream.for_role(
        args["password"].encode(),
        bytes.fromhex(args["server_random"]),
        bytes.fromhex(args["session_id"]),
        args["server"],
    )
    return {"frames": [stream.wrap(bytes.fromhex(message)).hex() for message in args["messages"]]}


def _server_random_case(args: dict) -> dict:
    found = server_random_of(bytes.fromhex(args["data"]))
    return {"server_random": found.hex() if found is not None else None}


def _server_name_case(args: dict) -> dict:
    return {"host": server_name_of(bytes.fromhex(args["data"]))}


def _split_records_case(args: dict) -> dict:
    records, leftover, opaque = split_records(bytes.fromhex(args["data"]))
    return {
        "records": [item.hex() for item in records],
        "leftover": leftover.hex(),
        "opaque": opaque,
    }


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list


FUNCTIONS: list[ParityFunction] = [
    ParityFunction(
        name="switch_token",
        python=_switch_token_case,
        cases=[
            {"password": "testpass", "server_random": SERVER_RANDOM.hex(), "session_id": SESSION_ID.hex()},
            {"password": "testpass", "server_random": "00" * 32, "session_id": "00" * 16},
            {"password": "testpass", "server_random": "ff" * 32, "session_id": "ff" * 16},
            {"password": "oldpass", "server_random": SERVER_RANDOM.hex(), "session_id": SESSION_ID.hex()},
            {"password": "пароль", "server_random": SERVER_RANDOM.hex(), "session_id": SESSION_ID.hex()},
        ],
    ),
    ParityFunction(
        name="switch_record",
        python=_switch_record_case,
        cases=[
            {
                "password": "testpass",
                "server_random": SERVER_RANDOM.hex(),
                "session_id": SESSION_ID.hex(),
                "padding": "",
            },
            {
                "password": "testpass",
                "server_random": SERVER_RANDOM.hex(),
                "session_id": SESSION_ID.hex(),
                "padding": "00" * 128,
            },
            {
                "password": "testpass",
                "server_random": "01" * 32,
                "session_id": "02" * 16,
                "padding": "ab" * 300,
            },
        ],
    ),
    ParityFunction(
        name="wrap",
        python=_wrap_case,
        cases=[
            {
                "password": "testpass",
                "server_random": SERVER_RANDOM.hex(),
                "session_id": SESSION_ID.hex(),
                "server": True,
                "messages": ["", "68656c6c6f", "00" * 100],
            },
            {
                "password": "testpass",
                "server_random": SERVER_RANDOM.hex(),
                "session_id": SESSION_ID.hex(),
                "server": False,
                "messages": ["68656c6c6f", "68656c6c6f"],
            },
            {
                "password": "testpass",
                "server_random": "01" * 32,
                "session_id": SESSION_ID.hex(),
                "server": True,
                "messages": ["5a" * (TLS_RECORD_MAX * 2 + 7)],
            },
        ],
    ),
    ParityFunction(
        name="server_random",
        python=_server_random_case,
        cases=[
            {"data": wrap_handshake(build_server_hello(SERVER_RANDOM)).hex()},
            {"data": build_server_hello(SERVER_RANDOM).hex()},
            {"data": build_server_hello(bytes(32)).hex()},
            {"data": wrap_handshake(build_client_hello(bytes(32), b"")).hex()},
            {"data": ""},
            {"data": wrap_handshake(build_server_hello(SERVER_RANDOM))[:20].hex()},
            {"data": "020000"},
        ],
    ),
    ParityFunction(
        name="server_name",
        python=_server_name_case,
        cases=[
            {"data": wrap_handshake(_HELLO_WITH_SNI).hex()},
            {"data": _HELLO_WITH_SNI.hex()},
            {"data": wrap_handshake(_HELLO_WITHOUT_SNI).hex()},
            {"data": wrap_handshake(_HELLO_UPPERCASE_SNI).hex()},
            {"data": wrap_handshake(_HELLO_BAD_SNI).hex()},
            {"data": wrap_handshake(_HELLO_EMPTY_SNI).hex()},
            {"data": ""},
            {"data": wrap_handshake(_HELLO_WITH_SNI)[:40].hex()},
            {"data": wrap_handshake(build_server_hello(SERVER_RANDOM)).hex()},
        ],
    ),
    ParityFunction(
        name="split_records",
        python=_split_records_case,
        cases=[
            {"data": (record(0x16, b"one") + record(0x17, b"two")).hex()},
            {"data": record(0x17, b"whole").hex()},
            {"data": record(0x17, b"whole")[:7].hex()},
            {"data": "1703"},
            {"data": b"GET / HTTP/1.1\r\n".hex()},
            {"data": "170303ffff"},
            {"data": (record(0x16, b"one") + b"GET /").hex()},
            {"data": "1702030004deadbeef"},
            {"data": ""},
        ],
    ),
]
