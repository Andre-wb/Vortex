"""Независимая Python-реализация формата Trojan.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная по спецификации реализация формата, против которой сверяется
`vortex-transport`. Формат публичный (trojan-go / xray / sing-box), поэтому
переносом он не менялся:

    запрос      = hex(SHA224(пароль))(56) ‖ CRLF ‖ заголовок ‖ CRLF ‖ payload
    заголовок   = cmd(1) ‖ atyp(1) ‖ адрес ‖ порт(2, big-endian)
    cmd         = 0x01 connect | 0x03 udp_associate
    atyp        = 0x01 IPv4(4) | 0x03 имя(1 байт длины ‖ байты) | 0x04 IPv6(16)

Разбор структурный: границы заголовка берутся из самого формата, а не поиском
первого CRLF — байты 0x0D 0x0A встречаются и внутри адреса (13.10.x.x), и
внутри порта (3338).

Исход разбора один из четырёх: accepted (хеш в реестре), unauthorized (формат
верный, хеш чужой), need_more (данных ещё не хватает), malformed (такой префикс
не станет запросом никогда).
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

PASSWORD_HASH_LEN = 28
PASSWORD_HASH_HEX_LEN = PASSWORD_HASH_LEN * 2
CRLF = b"\r\n"
HASH_FIELD_LEN = PASSWORD_HASH_HEX_LEN + len(CRLF)

CMD_CONNECT = 0x01
CMD_UDP_ASSOCIATE = 0x03
COMMANDS = {CMD_CONNECT: "connect", CMD_UDP_ASSOCIATE: "udp_associate"}

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

IPV4_LEN = 4
IPV6_LEN = 16
MAX_DOMAIN_FIELD_LEN = 255
MAX_HOST_LEN = 253

PORT_LEN = 2
MAX_REQUEST_HEADER_LEN = HASH_FIELD_LEN + 1 + 2 + MAX_DOMAIN_FIELD_LEN + PORT_LEN + len(CRLF)

HEX_DIGITS = set(b"0123456789abcdefABCDEF")

NEED_MORE = "need_more"
MALFORMED = "malformed"
ACCEPTED = "accepted"
UNAUTHORIZED = "unauthorized"

PROBE_TROJAN = "trojan"
PROBE_NEED_MORE = "need_more"
PROBE_NOT_TROJAN = "not_trojan"


def password_hash(password: bytes) -> Optional[str]:
    """Хеш пароля в том виде, в каком он едет по проводу. Пустой пароль — не пароль."""
    if not password:
        return None
    return hashlib.sha224(password).hexdigest()


def plausible_host(name: bytes) -> Optional[str]:
    if not name or len(name) > MAX_HOST_LEN:
        return None
    if not all(chr(b).isascii() and (chr(b).isalnum() or chr(b) in "-.") for b in name):
        return None
    return name.decode("ascii")


def encode_address(host: str) -> bytes:
    try:
        return bytes([ATYP_IPV4]) + ipaddress.IPv4Address(host).packed
    except ipaddress.AddressValueError:
        pass
    try:
        return bytes([ATYP_IPV6]) + ipaddress.IPv6Address(host).packed
    except ipaddress.AddressValueError:
        pass
    if len(host.encode()) > MAX_DOMAIN_FIELD_LEN or plausible_host(host.encode()) is None:
        raise ValueError(f"адрес назначения Trojan непредставим: {host}")
    name = host.encode()
    return bytes([ATYP_DOMAIN, len(name)]) + name


def encode_request(password: bytes, host: str, port: int, payload: bytes, command: int = CMD_CONNECT) -> bytes:
    digest = password_hash(password)
    if digest is None:
        raise ValueError("пароль Trojan не задан: запрос собрать нечем")
    return digest.encode() + CRLF + bytes([command]) + encode_address(host) + port.to_bytes(2, "big") + CRLF + payload


def probe(data: bytes) -> str:
    """Есть ли в начале потока 56 hex-символов и CRLF."""
    for byte in data[:PASSWORD_HASH_HEX_LEN]:
        if byte not in HEX_DIGITS:
            return PROBE_NOT_TROJAN
    for offset, expected in enumerate(CRLF):
        position = PASSWORD_HASH_HEX_LEN + offset
        if position >= len(data):
            return PROBE_NEED_MORE
        if data[position] != expected:
            return PROBE_NOT_TROJAN
    return PROBE_TROJAN


def _parse_address(data: bytes) -> tuple[Optional[str], Optional[str], Optional[int]]:
    """(вид адреса, хост, съедено байт); хост None — исход в первом элементе."""
    if not data:
        return NEED_MORE, None, None
    kind = data[0]
    if kind in (ATYP_IPV4, ATYP_IPV6):
        width = IPV4_LEN if kind == ATYP_IPV4 else IPV6_LEN
        if len(data) < 1 + width:
            return NEED_MORE, None, None
        address = ipaddress.ip_address(data[1 : 1 + width])
        return ("ipv4" if kind == ATYP_IPV4 else "ipv6"), str(address), 1 + width
    if kind == ATYP_DOMAIN:
        if len(data) < 2:
            return NEED_MORE, None, None
        length = data[1]
        if length == 0:
            return MALFORMED, None, None
        if len(data) < 2 + length:
            return NEED_MORE, None, None
        host = plausible_host(data[2 : 2 + length])
        if host is None:
            return MALFORMED, None, None
        return "domain", host, 2 + length
    return MALFORMED, None, None


def _parse_header(data: bytes) -> tuple[str, Optional[dict], int]:
    if not data:
        return NEED_MORE, None, 0
    command = COMMANDS.get(data[0])
    if command is None:
        return MALFORMED, None, 0
    kind, host, consumed = _parse_address(data[1:])
    if host is None:
        return kind, None, 0
    position = 1 + consumed
    if len(data) < position + PORT_LEN:
        return NEED_MORE, None, 0
    port = int.from_bytes(data[position : position + PORT_LEN], "big")
    position += PORT_LEN
    tail = data[position : position + len(CRLF)]
    if len(tail) < len(CRLF):
        return NEED_MORE, None, 0
    if tail != CRLF:
        return MALFORMED, None, 0
    header = {"command": command, "address_type": kind, "host": host, "port": port}
    return "parsed", header, position + len(CRLF)


def decode_request(passwords: list[bytes], data: bytes) -> dict:
    """Разбор запроса: исход и, если он accepted, разобранные поля."""
    refused = {
        "outcome": None,
        "password_hash": None,
        "command": None,
        "address_type": None,
        "host": None,
        "port": None,
        "payload": None,
    }
    prefix = probe(data)
    if prefix == PROBE_NOT_TROJAN:
        return {**refused, "outcome": MALFORMED}
    if prefix == PROBE_NEED_MORE:
        return {**refused, "outcome": NEED_MORE}
    digest = data[:PASSWORD_HASH_HEX_LEN].decode("ascii").lower()
    outcome, header, consumed = _parse_header(data[HASH_FIELD_LEN:])
    if header is None:
        return {**refused, "outcome": outcome}
    known = {password_hash(password) for password in passwords} - {None}
    if digest not in known:
        return {**refused, "outcome": UNAUTHORIZED}
    return {
        "outcome": ACCEPTED,
        "password_hash": digest,
        "command": header["command"],
        "address_type": header["address_type"],
        "host": header["host"],
        "port": header["port"],
        "payload": data[HASH_FIELD_LEN + consumed :].hex(),
    }


PASSWORD = b"testpass"
PREVIOUS_PASSWORD = b"oldpass"
EXTRA_PASSWORD = b"extrapass"
STRANGER_PASSWORD = b"otherpass"

_HASH = password_hash(PASSWORD).encode()


def _request(host: str, port: int, payload: bytes, password: bytes = PASSWORD) -> str:
    return encode_request(password, host, port, payload).hex()


def _broken(body: bytes) -> str:
    return (_HASH + CRLF + body).hex()


def _password_hash_case(args: dict) -> dict:
    return {"hash": password_hash(args["password"].encode())}


def _encode_request_case(args: dict) -> dict:
    return {
        "request": encode_request(
            args["password"].encode(),
            args["host"],
            args["port"],
            bytes.fromhex(args["payload"]),
        ).hex()
    }


def _decode_request_case(args: dict) -> dict:
    return decode_request(
        [password.encode() for password in args["passwords"]],
        bytes.fromhex(args["data"]),
    )


def _probe_case(args: dict) -> dict:
    return {"probe": probe(bytes.fromhex(args["data"]))}


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list


_ACCEPTED_REQUEST = _request("www.example.com", 443, b"GET / HTTP/1.1\r\n")
_CRLF_PORT_REQUEST = _request("www.example.com", 3338, b"payload")
_CRLF_ADDRESS_REQUEST = _request("13.10.13.10", 80, b"payload")
_IPV6_REQUEST = _request("2001:db8::1", 443, b"")
_STRANGER_REQUEST = _request("www.example.com", 443, b"x", password=STRANGER_PASSWORD)

FUNCTIONS: list[ParityFunction] = [
    ParityFunction(
        name="password_hash",
        python=_password_hash_case,
        cases=[
            {"password": "testpass"},
            {"password": "oldpass"},
            {"password": "extrapass"},
            {"password": "пароль"},
            {"password": ""},
        ],
    ),
    ParityFunction(
        name="encode_request",
        python=_encode_request_case,
        cases=[
            {"password": "testpass", "host": "www.example.com", "port": 443, "payload": "474554202f0d0a"},
            {"password": "testpass", "host": "13.10.1.2", "port": 443, "payload": ""},
            {"password": "testpass", "host": "13.10.13.10", "port": 80, "payload": "7061796c6f6164"},
            {"password": "testpass", "host": "www.example.com", "port": 3338, "payload": "7061796c6f6164"},
            {"password": "testpass", "host": "2001:db8::1", "port": 443, "payload": ""},
            {"password": "testpass", "host": "127.0.0.1", "port": 65535, "payload": "00ff0d0a"},
            {"password": "oldpass", "host": "www.example.com", "port": 443, "payload": ""},
            {"password": "пароль", "host": "www.example.com", "port": 443, "payload": ""},
        ],
    ),
    ParityFunction(
        name="decode_request",
        python=_decode_request_case,
        cases=[
            {"passwords": ["testpass"], "data": _ACCEPTED_REQUEST},
            {"passwords": ["testpass"], "data": _CRLF_PORT_REQUEST},
            {"passwords": ["testpass"], "data": _CRLF_ADDRESS_REQUEST},
            {"passwords": ["testpass"], "data": _IPV6_REQUEST},
            {"passwords": ["testpass"], "data": _request("13.10.1.2", 443, b"")},
            {"passwords": ["newpass", "testpass"], "data": _ACCEPTED_REQUEST},
            {"passwords": ["testpass"], "data": _STRANGER_REQUEST},
            {"passwords": [], "data": _ACCEPTED_REQUEST},
            {"passwords": ["testpass"], "data": _ACCEPTED_REQUEST[:80]},
            {"passwords": ["testpass"], "data": _ACCEPTED_REQUEST[: 2 * HASH_FIELD_LEN]},
            {"passwords": ["testpass"], "data": _CRLF_PORT_REQUEST[: 2 * (len(_CRLF_PORT_REQUEST) // 2 - 9)]},
            {"passwords": ["testpass"], "data": ""},
            {"passwords": ["testpass"], "data": "16030100050100000d"},
            {
                "passwords": ["testpass"],
                "data": (b"0x" + _HASH[2:] + CRLF + b"\x01\x01\x0d\x0a\x01\x02\x01\xbb\r\n").hex(),
            },
            {"passwords": ["testpass"], "data": _broken(b"\x02\x01\x0d\x0a\x01\x02\x01\xbb\r\n")},
            {"passwords": ["testpass"], "data": _broken(b"\x01\x02\x00\x00\x01\xbb\r\n")},
            {"passwords": ["testpass"], "data": _broken(b"\x01\x03\x00\x01\xbb\r\n")},
            {"passwords": ["testpass"], "data": _broken(b"\x01\x03\x07a b.com\x01\xbb\r\n")},
            {"passwords": ["testpass"], "data": _broken(b"\x01\x01\x0d\x0a\x01\x02\x01\xbb\x00\x00payload")},
        ],
    ),
    ParityFunction(
        name="probe",
        python=_probe_case,
        cases=[
            {"data": (_HASH + CRLF).hex()},
            {"data": (_HASH + CRLF + b"payload").hex()},
            {"data": _HASH.hex()},
            {"data": (_HASH + b"\r").hex()},
            {"data": _HASH[:10].hex()},
            {"data": ""},
            {"data": (_HASH.upper() + CRLF).hex()},
            {"data": (b"0x" + _HASH[2:] + CRLF).hex()},
            {"data": (b"1_" + _HASH[2:] + CRLF).hex()},
            {"data": (b"+4" + _HASH[2:] + CRLF).hex()},
            {"data": (b" 4" + _HASH[2:] + CRLF).hex()},
            {"data": (_HASH + b"  ").hex()},
            {"data": (_HASH + b"\r ").hex()},
            {"data": "16030100050100000d"},
            {"data": b"GET / HTTP/1.1\r\n".hex()},
        ],
    ),
]
