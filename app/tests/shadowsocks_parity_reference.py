"""Независимая Python-реализация формата Shadowsocks.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная по спецификации реализация формата, против которой сверяется
`vortex-transport`.

Формат v2, несовместимый с v1 (в v1 каждый пакет нёс свою соль и свой ключ,
адрес назначения выбрасывался при разборе, повтор пакета не отслеживался
ничем, а границы кадра в потоке не существовало):

    ключ пароля  = HKDF-SHA256(ikm = пароль, salt = нет, "vortex-shadowsocks-password-v2", 32)
    пролог       = соль сеанса (32 случайных байта, шлёт клиент первым)
    ключ c2s/s2c = HKDF-SHA256(ikm = ключ пароля, salt = соль, метка направления, 32)
    кадр         = AES-256-GCM(длина тела u16 BE)  [18 байт, nonce = счётчик]
                 ‖ AES-256-GCM(тело)               [длина тела + 16, nonce = счётчик + 1]
    nonce        = счётчик u64 BE в младших восьми байтах двенадцати нулей
    первый кадр  = atyp ‖ адрес ‖ порт(2 BE) ‖ pad_len(2 BE) ‖ паддинг ‖ данные
    atyp         = 0x01 IPv4(4) | 0x03 имя(1 байт длины ‖ байты) | 0x04 IPv6(16)

Счётчик тратит два значения на кадр: одно на длину, одно на тело. AAD нет —
номер операции уже входит в nonce.

Исход разбора потока один из четырёх: accepted (кадр открылся ключом из
реестра), unauthorized (ни один пароль не подошёл), need_more (данных ещё не
хватает), malformed (открылось, но телом запроса не является).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PASSWORD_INFO = b"vortex-shadowsocks-password-v2"
DATA_CLIENT_LABEL = b"vortex-shadowsocks data c2s v2"
DATA_SERVER_LABEL = b"vortex-shadowsocks data s2c v2"

SALT_LEN = 32
KEY_LEN = 32
LENGTH_LEN = 2
TAG_LEN = 16
NONCE_LEN = 12
LENGTH_CHUNK_LEN = LENGTH_LEN + TAG_LEN

MAX_PAYLOAD = 16384
MAX_FRAME = LENGTH_CHUNK_LEN + MAX_PAYLOAD + TAG_LEN
MAX_PADDING = 1024
PADDING_LEN_LEN = 2

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

IPV4_LEN = 4
IPV6_LEN = 16
MAX_DOMAIN_FIELD_LEN = 255
MAX_HOST_LEN = 253
PORT_LEN = 2

CLIENT = "client"
SERVER = "server"

OPENED = "opened"
NEED_MORE = "need_more"
MALFORMED = "malformed"
ACCEPTED = "accepted"
UNAUTHORIZED = "unauthorized"

PASSWORD = b"test_password"
PREVIOUS_PASSWORD = b"old_password"
STRANGER_PASSWORD = b"other_password"


def password_key(password: bytes) -> Optional[bytes]:
    """Ключ пароля. Пустой пароль — не пароль, транспорт остаётся ненастроенным."""
    if not password:
        return None
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=PASSWORD_INFO).derive(password)


def direction_keys(key: bytes, salt: bytes, role: str) -> tuple[bytes, bytes]:
    """(ключ отправки, ключ приёма) для роли. Клиент шлёт c2s, сервер — s2c."""
    labels = {CLIENT: (DATA_CLIENT_LABEL, DATA_SERVER_LABEL), SERVER: (DATA_SERVER_LABEL, DATA_CLIENT_LABEL)}
    send_label, recv_label = labels[role]
    return (
        HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=send_label).derive(key),
        HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=recv_label).derive(key),
    )


def nonce(counter: int) -> bytes:
    return b"\x00" * (NONCE_LEN - 8) + counter.to_bytes(8, "big")


def plausible_host(name: bytes) -> Optional[str]:
    """Правило «что может быть именем хоста» — одно на SNI, Trojan и Shadowsocks."""
    if not name or len(name) > MAX_HOST_LEN:
        return None
    allowed = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    if any(byte not in allowed for byte in name):
        return None
    return name.decode("ascii")


def encode_destination(host: str, port: int) -> Optional[bytes]:
    """atyp ‖ адрес ‖ порт. Имя проверяется, IPv6 не уезжает как имя."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = plausible_host(host.encode("utf-8", errors="replace") if host else b"")
        if name is None:
            return None
        return bytes([ATYP_DOMAIN, len(name)]) + name.encode() + port.to_bytes(PORT_LEN, "big")
    kind = ATYP_IPV4 if address.version == 4 else ATYP_IPV6
    return bytes([kind]) + address.packed + port.to_bytes(PORT_LEN, "big")


def decode_destination(body: bytes) -> Optional[tuple[str, int, int]]:
    """(хост, порт, сколько байт съедено) либо None. Разбор структурный."""
    if not body:
        return None
    kind = body[0]
    if kind == ATYP_IPV4:
        end = 1 + IPV4_LEN
        if len(body) < end + PORT_LEN:
            return None
        host = str(ipaddress.IPv4Address(body[1:end]))
    elif kind == ATYP_IPV6:
        end = 1 + IPV6_LEN
        if len(body) < end + PORT_LEN:
            return None
        host = str(ipaddress.IPv6Address(body[1:end]))
    elif kind == ATYP_DOMAIN:
        if len(body) < 2:
            return None
        name_len = body[1]
        end = 2 + name_len
        if name_len == 0 or len(body) < end + PORT_LEN:
            return None
        name = plausible_host(body[2:end])
        if name is None:
            return None
        host = name
    else:
        return None
    port = int.from_bytes(body[end : end + PORT_LEN], "big")
    return host, port, end + PORT_LEN


def encode_request_body(host: str, port: int, padding: bytes, payload: bytes) -> Optional[bytes]:
    """Тело первого кадра: назначение, длина паддинга, паддинг, данные."""
    if len(padding) > MAX_PADDING:
        return None
    destination = encode_destination(host, port)
    if destination is None:
        return None
    return destination + len(padding).to_bytes(PADDING_LEN_LEN, "big") + padding + payload


def decode_request_body(body: bytes) -> Optional[tuple[str, int, bytes]]:
    """(хост, порт, данные) либо None. Паддинг обязан помещаться в тело."""
    parsed = decode_destination(body)
    if parsed is None:
        return None
    host, port, consumed = parsed
    rest = body[consumed:]
    if len(rest) < PADDING_LEN_LEN:
        return None
    padding_len = int.from_bytes(rest[:PADDING_LEN_LEN], "big")
    if padding_len > MAX_PADDING or len(rest) < PADDING_LEN_LEN + padding_len:
        return None
    return host, port, rest[PADDING_LEN_LEN + padding_len :]


def seal_frame(key: bytes, counter: int, body: bytes) -> Optional[bytes]:
    """Один кадр. Пустое тело и тело сверх предела кадром не становятся."""
    if not body or len(body) > MAX_PAYLOAD:
        return None
    cipher = AESGCM(key)
    length = cipher.encrypt(nonce(counter), len(body).to_bytes(LENGTH_LEN, "big"), None)
    sealed = cipher.encrypt(nonce(counter + 1), body, None)
    return length + sealed


def seal_stream(key: bytes, counter: int, data: bytes) -> tuple[bytes, int]:
    """Данные, нарезанные на кадры. Нечего слать — нечего и отправлять."""
    out = b""
    offset = 0
    while offset < len(data):
        end = min(len(data), offset + MAX_PAYLOAD)
        out += seal_frame(key, counter, data[offset:end])
        counter += 2
        offset = end
    return out, counter


def open_frame(key: bytes, counter: int, buffer: bytes) -> tuple[str, Optional[bytes], int]:
    """(исход, тело, сколько байт съедено). Счётчик двигает только вызывающий."""
    if len(buffer) < LENGTH_CHUNK_LEN:
        return NEED_MORE, None, 0
    cipher = AESGCM(key)
    try:
        declared = cipher.decrypt(nonce(counter), buffer[:LENGTH_CHUNK_LEN], None)
    except Exception:
        return MALFORMED, None, 0
    payload_len = int.from_bytes(declared, "big")
    if payload_len == 0 or payload_len > MAX_PAYLOAD:
        return MALFORMED, None, 0
    whole = LENGTH_CHUNK_LEN + payload_len + TAG_LEN
    if len(buffer) < whole:
        return NEED_MORE, None, 0
    try:
        body = cipher.decrypt(nonce(counter + 1), buffer[LENGTH_CHUNK_LEN:whole], None)
    except Exception:
        return MALFORMED, None, 0
    return OPENED, body, whole


def drain(key: bytes, counter: int, buffer: bytes) -> tuple[str, bytes, int, int]:
    """(исход, данные, сколько байт съедено, счётчик). Хвост остаётся вызывающему."""
    data = b""
    offset = 0
    while offset < len(buffer):
        outcome, body, consumed = open_frame(key, counter, buffer[offset:])
        if outcome == MALFORMED:
            return MALFORMED, b"", offset, counter
        if outcome == NEED_MORE:
            break
        data += body
        offset += consumed
        counter += 2
    return OPENED, data, offset, counter


def seal_handshake(password: bytes, salt: bytes, padding: bytes, host: str, port: int, data: bytes) -> Optional[bytes]:
    """Поток клиента целиком: пролог, запрос, кадры данных, что не влезли в запрос."""
    key = password_key(password)
    if key is None:
        return None
    send, _ = direction_keys(key, salt, CLIENT)
    head = encode_request_body(host, port, padding, b"")
    if head is None:
        return None
    taken = min(len(data), max(0, MAX_PAYLOAD - len(head)))
    first = seal_frame(send, 0, head + data[:taken])
    if first is None:
        return None
    rest, _ = seal_stream(send, 2, data[taken:])
    return salt + first + rest


def open_handshake(passwords: list[bytes], stream: bytes) -> dict:
    """Разбор потока клиента серверной стороной. Пароли обходятся все, без раннего выхода."""
    empty = {"outcome": None, "host": None, "port": None, "payload": None, "consumed": 0}
    if len(stream) < SALT_LEN:
        return {**empty, "outcome": NEED_MORE}
    salt = stream[:SALT_LEN]
    buffer = stream[SALT_LEN:]
    if len(buffer) < LENGTH_CHUNK_LEN:
        return {**empty, "outcome": NEED_MORE}

    winner = None
    incomplete = False
    for password in passwords:
        key = password_key(password)
        if key is None:
            continue
        _, recv = direction_keys(key, salt, SERVER)
        outcome, body, consumed = open_frame(recv, 0, buffer)
        if outcome == OPENED and winner is None:
            winner = (body, consumed)
        elif outcome == NEED_MORE:
            incomplete = True

    if winner is None:
        return {**empty, "outcome": NEED_MORE if incomplete else UNAUTHORIZED}
    body, consumed = winner
    parsed = decode_request_body(body)
    if parsed is None:
        return {**empty, "outcome": MALFORMED}
    host, port, payload = parsed
    return {
        "outcome": ACCEPTED,
        "host": host,
        "port": port,
        "payload": payload.hex(),
        "consumed": SALT_LEN + consumed,
    }


def _password_key_case(args: dict) -> dict:
    key = password_key(args["password"].encode())
    return {"key": key.hex() if key is not None else None}


def _direction_keys_case(args: dict) -> dict:
    key = password_key(args["password"].encode())
    send, recv = direction_keys(key, bytes.fromhex(args["salt"]), args["role"])
    return {"send": send.hex(), "recv": recv.hex()}


def _seal_handshake_case(args: dict) -> dict:
    stream = seal_handshake(
        args["password"].encode(),
        bytes.fromhex(args["salt"]),
        bytes.fromhex(args["padding"]),
        args["host"],
        args["port"],
        bytes.fromhex(args["data"]),
    )
    return {"stream": stream.hex() if stream is not None else None}


def _open_handshake_case(args: dict) -> dict:
    return open_handshake([p.encode() for p in args["passwords"]], bytes.fromhex(args["stream"]))


def seal_start_counter(role: str) -> int:
    """Клиент уже потратил кадр на запрос; сервер ещё не сказал ничего."""
    return 2 if role == CLIENT else 0


def open_start_counter(role: str) -> int:
    """Счётчик направления, которое эта сторона читает."""
    return 2 if role == SERVER else 0


def _seal_frames_case(args: dict) -> dict:
    key = password_key(args["password"].encode())
    send, _ = direction_keys(key, bytes.fromhex(args["salt"]), args["role"])
    stream, counter = seal_stream(send, seal_start_counter(args["role"]), bytes.fromhex(args["data"]))
    return {"frames": stream.hex(), "counter": counter}


def _open_frames_case(args: dict) -> dict:
    key = password_key(args["password"].encode())
    _, recv = direction_keys(key, bytes.fromhex(args["salt"]), args["role"])
    outcome, data, consumed, counter = drain(recv, open_start_counter(args["role"]), bytes.fromhex(args["buffer"]))
    if outcome == MALFORMED:
        return {"outcome": MALFORMED, "data": None, "consumed": 0, "counter": 0}
    return {"outcome": outcome, "data": data.hex(), "consumed": consumed, "counter": counter}


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list


_SALT = ("11" * SALT_LEN, "22" * SALT_LEN)


def _stream(host: str, port: int, data: bytes, padding: bytes = b"", password: bytes = PASSWORD) -> str:
    return seal_handshake(password, bytes.fromhex(_SALT[0]), padding, host, port, data).hex()


def _frames(*bodies: bytes, role: str = CLIENT, password: bytes = PASSWORD, salt: str = _SALT[0]) -> str:
    """Кадры, которые эта роль шлёт после рукопожатия."""
    key = password_key(password)
    send, _ = direction_keys(key, bytes.fromhex(salt), role)
    out = b""
    counter = seal_start_counter(role)
    for body in bodies:
        chunk, counter = seal_stream(send, counter, body)
        out += chunk
    return out.hex()


def _sealed_request_body(body: bytes, password: bytes = PASSWORD) -> str:
    """Первый кадр с правильным ключом, но телом, которое запросом не является."""
    key = password_key(password)
    send, _ = direction_keys(key, bytes.fromhex(_SALT[0]), CLIENT)
    return (bytes.fromhex(_SALT[0]) + seal_frame(send, 0, body)).hex()


def _tampered(stream_hex: str, index: int) -> str:
    raw = bytearray(bytes.fromhex(stream_hex))
    raw[index] ^= 0x01
    return bytes(raw).hex()


_ACCEPTED = _stream("www.example.com", 9000, b"hello ss")
_PADDED = _stream("www.example.com", 9000, b"hello ss", padding=bytes(64))
_IPV4 = _stream("13.10.1.2", 443, b"payload")
_IPV6 = _stream("2001:db8::1", 443, b"")
_STRANGER = _stream("www.example.com", 9000, b"x", password=STRANGER_PASSWORD)

FUNCTIONS: list[ParityFunction] = [
    ParityFunction(
        name="password_key",
        python=_password_key_case,
        cases=[
            {"password": "test_password"},
            {"password": "old_password"},
            {"password": "other_password"},
            {"password": "пароль"},
            {"password": ""},
        ],
    ),
    ParityFunction(
        name="direction_keys",
        python=_direction_keys_case,
        cases=[
            {"password": "test_password", "salt": _SALT[0], "role": CLIENT},
            {"password": "test_password", "salt": _SALT[0], "role": SERVER},
            {"password": "test_password", "salt": _SALT[1], "role": CLIENT},
            {"password": "old_password", "salt": _SALT[0], "role": CLIENT},
            {"password": "пароль", "salt": _SALT[0], "role": SERVER},
        ],
    ),
    ParityFunction(
        name="seal_handshake",
        python=_seal_handshake_case,
        cases=[
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "www.example.com",
                "port": 9000,
                "data": b"hello ss".hex(),
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": ("aa" * 64),
                "host": "www.example.com",
                "port": 9000,
                "data": b"hello ss".hex(),
            },
            {
                "password": "test_password",
                "salt": _SALT[1],
                "padding": "",
                "host": "www.example.com",
                "port": 9000,
                "data": b"hello ss".hex(),
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "13.10.1.2",
                "port": 443,
                "data": b"payload".hex(),
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "2001:db8::1",
                "port": 443,
                "data": "",
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "13.10.13.10",
                "port": 3338,
                "data": b"payload".hex(),
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": ("00" * MAX_PADDING),
                "host": "a.example",
                "port": 1,
                "data": "",
            },
            {
                "password": "old_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "www.example.com",
                "port": 9000,
                "data": "",
            },
            {
                "password": "пароль",
                "salt": _SALT[0],
                "padding": "",
                "host": "www.example.com",
                "port": 9000,
                "data": "",
            },
            {
                "password": "",
                "salt": _SALT[0],
                "padding": "",
                "host": "www.example.com",
                "port": 9000,
                "data": "",
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": ("00" * (MAX_PADDING + 1)),
                "host": "www.example.com",
                "port": 9000,
                "data": "",
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "he re.com",
                "port": 9000,
                "data": "",
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "",
                "port": 9000,
                "data": "",
            },
            {
                "password": "test_password",
                "salt": _SALT[0],
                "padding": "",
                "host": "звезда.рф",
                "port": 9000,
                "data": "",
            },
        ],
    ),
    ParityFunction(
        name="open_handshake",
        python=_open_handshake_case,
        cases=[
            {"passwords": ["test_password"], "stream": _ACCEPTED},
            {"passwords": ["test_password"], "stream": _PADDED},
            {"passwords": ["test_password"], "stream": _IPV4},
            {"passwords": ["test_password"], "stream": _IPV6},
            {"passwords": ["new_password", "test_password"], "stream": _ACCEPTED},
            {"passwords": ["test_password"], "stream": _STRANGER},
            {"passwords": [], "stream": _ACCEPTED},
            {"passwords": [""], "stream": _ACCEPTED},
            {"passwords": [], "stream": _ACCEPTED[: 2 * (SALT_LEN + LENGTH_CHUNK_LEN - 1)]},
            {"passwords": [], "stream": _ACCEPTED[: 2 * (SALT_LEN + LENGTH_CHUNK_LEN)]},
            {"passwords": ["test_password"], "stream": ""},
            {"passwords": ["test_password"], "stream": _ACCEPTED[: 2 * (SALT_LEN - 1)]},
            {"passwords": ["test_password"], "stream": _ACCEPTED[: 2 * SALT_LEN]},
            {"passwords": ["test_password"], "stream": _ACCEPTED[: 2 * (SALT_LEN + LENGTH_CHUNK_LEN)]},
            {"passwords": ["test_password"], "stream": _ACCEPTED[:-2]},
            {"passwords": ["test_password"], "stream": _tampered(_ACCEPTED, SALT_LEN)},
            {"passwords": ["test_password"], "stream": _tampered(_ACCEPTED, len(_ACCEPTED) // 2 - 1)},
            {"passwords": ["test_password"], "stream": ("00" * SALT_LEN) + ("00" * LENGTH_CHUNK_LEN)},
            {"passwords": ["test_password"], "stream": _sealed_request_body(b"\x02\x00\x00\x00\x00\x00")},
            {"passwords": ["test_password"], "stream": _sealed_request_body(b"\x03\x07a b.com\x23\x28\x00\x00")},
            {"passwords": ["test_password"], "stream": _sealed_request_body(b"\x01\x0d\x0a\x01\x02\x23\x28")},
            {"passwords": ["test_password"], "stream": _sealed_request_body(b"\x01\x0d\x0a\x01\x02\x23\x28\x00\x09")},
            {"passwords": ["test_password"], "stream": _sealed_request_body(b"\x03\x00\x23\x28\x00\x00")},
        ],
    ),
    ParityFunction(
        name="seal_frames",
        python=_seal_frames_case,
        cases=[
            {"password": "test_password", "salt": _SALT[0], "role": CLIENT, "data": b"ping".hex()},
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "data": b"pong".hex()},
            {"password": "test_password", "salt": _SALT[1], "role": CLIENT, "data": b"ping".hex()},
            {"password": "test_password", "salt": _SALT[0], "role": CLIENT, "data": ""},
            {"password": "test_password", "salt": _SALT[0], "role": CLIENT, "data": "00" * MAX_PAYLOAD},
            {"password": "test_password", "salt": _SALT[0], "role": CLIENT, "data": "41" * (MAX_PAYLOAD + 7)},
            {"password": "old_password", "salt": _SALT[0], "role": CLIENT, "data": b"ping".hex()},
        ],
    ),
    ParityFunction(
        name="open_frames",
        python=_open_frames_case,
        cases=[
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": _frames(b"ping")},
            {"password": "test_password", "salt": _SALT[0], "role": CLIENT, "buffer": _frames(b"pong", role=SERVER)},
            {
                "password": "test_password",
                "salt": _SALT[0],
                "role": SERVER,
                "buffer": _frames(b"A" * (MAX_PAYLOAD + 7)),
            },
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": ""},
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": _frames(b"ping")[:-2]},
            {
                "password": "test_password",
                "salt": _SALT[0],
                "role": SERVER,
                "buffer": _frames(b"ping", b"pong")[: -2 * 10],
            },
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": _frames(b"ping", b"pong")},
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": _tampered(_frames(b"ping"), 0)},
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": _tampered(_frames(b"ping"), 30)},
            {"password": "test_password", "salt": _SALT[1], "role": SERVER, "buffer": _frames(b"ping")},
            {"password": "other_password", "salt": _SALT[0], "role": SERVER, "buffer": _frames(b"ping")},
            {"password": "test_password", "salt": _SALT[0], "role": SERVER, "buffer": "00" * LENGTH_CHUNK_LEN},
        ],
    ),
]
