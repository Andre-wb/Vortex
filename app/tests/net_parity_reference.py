"""Независимая Python-реализация формата UDP-обнаружения узлов Vortex.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная реализация формата провода, против которой сверяется крейт
`vortex-net`. Формат:

    конверт discovery  = компактный JSON {"name","port","pubkey"?} (UTF-8)
    разбор конверта    = нормализация как в приёмнике (обрезка имени до 64
                         символов, валидация pubkey 64-hex, диапазон порта)
    stealth-конверт    = nonce(8) ‖ payload[i] ^ K[(i + nonce[i mod 8]) mod 32]
                         где K = SHA-256(network_key)
    subnet broadcast   = "a.b.c.255" для IPv4, иначе "255.255.255.255"
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

NAME_MAX_CHARS = 64
PUBKEY_HEX_LEN = 64
STEALTH_KEY_LEN = 32
STEALTH_NONCE_LEN = 8
GLOBAL_BROADCAST = "255.255.255.255"

_HEX_ALPHABET = set("0123456789abcdefABCDEF")


def encode(name: str, port: int, pubkey: Optional[str]) -> bytes:
    obj: dict = {"name": name, "port": port}
    if pubkey is not None:
        obj["pubkey"] = pubkey
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_hex(text: str) -> bool:
    return all(character in _HEX_ALPHABET for character in text)


def _normalize_pubkey(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if len(value) != PUBKEY_HEX_LEN:
        return None
    if not _is_hex(value):
        return None
    return value


def _coerce_port(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def decode(frame: bytes, fallback_name: str, fallback_port: int) -> Optional[dict]:
    try:
        obj = json.loads(frame)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None

    raw_name = obj.get("name")
    name = raw_name if isinstance(raw_name, str) else fallback_name
    name = "".join(list(name)[:NAME_MAX_CHARS])

    if "port" not in obj:
        port = fallback_port
    else:
        port = _coerce_port(obj.get("port"))
        if port is None:
            return None
    if not (1 <= port <= 65535):
        return None

    pubkey = _normalize_pubkey(obj.get("pubkey"))
    return {"name": name, "port": port, "pubkey": pubkey}


def _keystream_byte(key: bytes, nonce: bytes, index: int) -> int:
    return key[(index + nonce[index % STEALTH_NONCE_LEN]) % STEALTH_KEY_LEN]


def stealth_seal(payload: bytes, network_key: bytes, nonce: bytes) -> bytes:
    key = hashlib.sha256(network_key).digest()
    out = bytearray(nonce)
    for index, byte in enumerate(payload):
        out.append(byte ^ _keystream_byte(key, nonce, index))
    return bytes(out)


def stealth_open(data: bytes, network_key: bytes) -> Optional[bytes]:
    if len(data) < STEALTH_NONCE_LEN + 1:
        return None
    nonce = data[:STEALTH_NONCE_LEN]
    ciphertext = data[STEALTH_NONCE_LEN:]
    key = hashlib.sha256(network_key).digest()
    out = bytearray()
    for index, byte in enumerate(ciphertext):
        out.append(byte ^ _keystream_byte(key, nonce, index))
    return bytes(out)


def subnet_broadcast(ip: str) -> str:
    octets = ip.split(".")
    if len(octets) == 4:
        return f"{octets[0]}.{octets[1]}.{octets[2]}.255"
    return GLOBAL_BROADCAST


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], object]
    cases: list[dict]


def _encode_case(args: dict) -> dict:
    return {"frame": encode(args["name"], args["port"], args.get("pubkey")).hex()}


def _decode_case(args: dict):
    return decode(bytes.fromhex(args["frame"]), args["fallback_name"], args["fallback_port"])


def _seal_case(args: dict) -> dict:
    sealed = stealth_seal(
        bytes.fromhex(args["payload"]),
        bytes.fromhex(args["network_key"]),
        bytes.fromhex(args["nonce"]),
    )
    return {"sealed": sealed.hex()}


def _open_case(args: dict):
    opened = stealth_open(bytes.fromhex(args["data"]), bytes.fromhex(args["network_key"]))
    return None if opened is None else {"opened": opened.hex()}


def _subnet_case(args: dict) -> dict:
    return {"broadcast": subnet_broadcast(args["ip"])}


NETWORK_KEY = b"vortex-shared-network-key".hex()
NONCE = "0102030405060708"

_FRAME_FULL = encode("alice", 9000, "ab" * 32).hex()
_FRAME_NO_PUBKEY = encode("alice", 9000, None).hex()
_FRAME_UNICODE = encode("узел-北京", 443, None).hex()
_FRAME_LONG_NAME = encode("x" * 100, 9000, None).hex()
_FRAME_MISSING_NAME = b'{"port":9000}'.hex()
_FRAME_MISSING_PORT = b'{"name":"solo"}'.hex()
_FRAME_BAD_PUBKEY_LEN = b'{"name":"n","port":9000,"pubkey":"abcd"}'.hex()
_FRAME_BAD_PUBKEY_HEX = ('{"name":"n","port":9000,"pubkey":"' + "z" * 64 + '"}').encode().hex()
_FRAME_NULL_PUBKEY = b'{"name":"n","port":9000,"pubkey":null}'.hex()
_FRAME_PORT_STRING = b'{"name":"n","port":"9000"}'.hex()
_FRAME_PORT_FLOAT = b'{"name":"n","port":9000.9}'.hex()
_FRAME_PORT_ZERO = b'{"name":"n","port":0}'.hex()
_FRAME_PORT_HIGH = b'{"name":"n","port":70000}'.hex()
_FRAME_PORT_BOOL = b'{"name":"n","port":true}'.hex()
_FRAME_PORT_NULL = b'{"name":"n","port":null}'.hex()
_FRAME_NAME_NUMBER = b'{"name":5,"port":9000}'.hex()
_FRAME_ARRAY = b"[1,2,3]".hex()
_FRAME_BROKEN = b"not json".hex()
_FRAME_EMPTY = b"".hex()

_SEAL_SAMPLE = stealth_seal(bytes.fromhex(_FRAME_NO_PUBKEY), bytes.fromhex(NETWORK_KEY), bytes.fromhex(NONCE)).hex()

FUNCTIONS = [
    ParityFunction(
        name="encode",
        python=_encode_case,
        cases=[
            {"name": "alice", "port": 9000, "pubkey": "ab" * 32},
            {"name": "alice", "port": 9000, "pubkey": None},
            {"name": "узел-北京", "port": 443, "pubkey": None},
            {"name": "", "port": 1, "pubkey": None},
            {"name": "x" * 100, "port": 9000, "pubkey": None},
            {"name": "host", "port": 65535, "pubkey": "ff" * 32},
            {"name": 'a"b\\c/d', "port": 8080, "pubkey": None},
        ],
    ),
    ParityFunction(
        name="decode",
        python=_decode_case,
        cases=[
            {"frame": _FRAME_FULL, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_NO_PUBKEY, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_UNICODE, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_LONG_NAME, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_MISSING_NAME, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_MISSING_PORT, "fallback_name": "1.2.3.4", "fallback_port": 8123},
            {"frame": _FRAME_BAD_PUBKEY_LEN, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_BAD_PUBKEY_HEX, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_NULL_PUBKEY, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_PORT_STRING, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_PORT_FLOAT, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_PORT_ZERO, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_PORT_HIGH, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_PORT_BOOL, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_PORT_NULL, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_NAME_NUMBER, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_ARRAY, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_BROKEN, "fallback_name": "1.2.3.4", "fallback_port": 8000},
            {"frame": _FRAME_EMPTY, "fallback_name": "1.2.3.4", "fallback_port": 8000},
        ],
    ),
    ParityFunction(
        name="stealth_seal",
        python=_seal_case,
        cases=[
            {"payload": b"beacon".hex(), "network_key": NETWORK_KEY, "nonce": NONCE},
            {"payload": _FRAME_NO_PUBKEY, "network_key": NETWORK_KEY, "nonce": "ff" * 8},
            {"payload": "", "network_key": NETWORK_KEY, "nonce": "00" * 8},
            {"payload": "00ff8040", "network_key": "00", "nonce": "1122334455667788"},
        ],
    ),
    ParityFunction(
        name="stealth_open",
        python=_open_case,
        cases=[
            {"data": _SEAL_SAMPLE, "network_key": NETWORK_KEY},
            {"data": "1122334455", "network_key": NETWORK_KEY},
            {"data": "00" * 8, "network_key": NETWORK_KEY},
            {"data": "00" * 9, "network_key": NETWORK_KEY},
            {"data": _SEAL_SAMPLE, "network_key": b"different-key".hex()},
        ],
    ),
    ParityFunction(
        name="subnet_broadcast",
        python=_subnet_case,
        cases=[
            {"ip": "192.168.1.20"},
            {"ip": "10.0.0.5"},
            {"ip": "127.0.0.1"},
            {"ip": ""},
            {"ip": "abc"},
            {"ip": "1.2.3"},
            {"ip": "1.2.3.4.5"},
            {"ip": "a.b.c.d"},
        ],
    ),
]
