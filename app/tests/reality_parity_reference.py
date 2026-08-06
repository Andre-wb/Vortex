"""Эталонные Python-реализации REALITY-аутентификации.

Замороженный снимок логики, которая до переноса в Rust жила в
`app/transport/stealth_level4.py::RealityProtocol`. Существует только ради
golden-векторов: `vortex-transport` обязан совпадать с этими функциями
байт-в-байт. Продуктовый код их не импортирует.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ENVELOPE_VERSION = 1
AUTH_INFO = b"vortex-reality"
AUTH_KEY_LEN = 16
NONCE_LEN = 12
KEY_SHARE_EXTENSION = 0x0033
GROUP_X25519 = 0x001D


def auth_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=AUTH_KEY_LEN, salt=None, info=AUTH_INFO).derive(shared)


def nonce_for(ephemeral_pub: bytes) -> bytes:
    return hashlib.sha256(ephemeral_pub).digest()[:NONCE_LEN]


def encode_envelope(timestamp: int, short_id_hex: str) -> bytes:
    return struct.pack(">Bq", ENVELOPE_VERSION, timestamp) + bytes.fromhex(short_id_hex)


def public_key_of(secret_hex: str) -> bytes:
    private = X25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex))
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def seal(secret_hex: str, server_public_hex: str, timestamp: int, short_id_hex: str) -> tuple[bytes, bytes]:
    ephemeral = X25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex))
    ephemeral_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(server_public_hex)))
    key = auth_key(shared)
    plaintext = encode_envelope(timestamp, short_id_hex)
    session_id = AESGCM(key).encrypt(nonce_for(ephemeral_pub), plaintext, ephemeral_pub)
    return ephemeral_pub, session_id


def open_envelope(secret_hex: str, ephemeral_pub: bytes, session_id: bytes) -> Optional[tuple[int, int, str]]:
    try:
        private = X25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex))
        shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
        plaintext = AESGCM(auth_key(shared)).decrypt(nonce_for(ephemeral_pub), session_id, ephemeral_pub)
    except Exception:
        return None
    if len(plaintext) < 9:
        return None
    version, timestamp = struct.unpack(">Bq", plaintext[:9])
    return version, timestamp, plaintext[9:].hex()


def parse_client_hello(data: bytes) -> Optional[tuple[bytes, bytes]]:
    try:
        buf = data[5:] if data and data[0] == 0x16 else data
        if len(buf) < 4 or buf[0] != 0x01:
            return None
        pos = 4 + 2 + 32
        if pos + 1 > len(buf):
            return None
        sid_len = buf[pos]
        pos += 1
        session_id = buf[pos : pos + sid_len]
        pos += sid_len
        if pos + 2 > len(buf):
            return None
        pos += 2 + int.from_bytes(buf[pos : pos + 2], "big")
        if pos + 1 > len(buf):
            return None
        pos += 1 + buf[pos]
        if pos + 2 > len(buf):
            return None
        end = min(len(buf), pos + 2 + int.from_bytes(buf[pos : pos + 2], "big"))
        pos += 2
        key_share = b""
        while pos + 4 <= end:
            etype = int.from_bytes(buf[pos : pos + 2], "big")
            elen = int.from_bytes(buf[pos + 2 : pos + 4], "big")
            body = buf[pos + 4 : pos + 4 + elen]
            pos += 4 + elen
            if etype != KEY_SHARE_EXTENSION:
                continue
            p = 2
            while p + 4 <= len(body):
                group = int.from_bytes(body[p : p + 2], "big")
                klen = int.from_bytes(body[p + 2 : p + 4], "big")
                kv = body[p + 4 : p + 4 + klen]
                p += 4 + klen
                if group == GROUP_X25519 and len(kv) == 32:
                    key_share = kv
                    break
        return session_id, key_share
    except Exception:
        return None


def build_key_share_extension(key: bytes) -> bytes:
    entry = struct.pack(">HH", GROUP_X25519, len(key)) + key
    body = struct.pack(">H", len(entry)) + entry
    return struct.pack(">HH", KEY_SHARE_EXTENSION, len(body)) + body


def build_client_hello(session_id: bytes, extensions: bytes) -> bytes:
    body = b"\x03\x03" + b"\x00" * 32
    body += bytes([len(session_id)]) + session_id
    body += b"\x00\x02\x13\x01"
    body += b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    return b"\x01" + len(body).to_bytes(3, "big") + body


def wrap_tls_record(handshake: bytes) -> bytes:
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list[dict]


def _seal_case(args: dict) -> dict:
    ephemeral_pub, session_id = seal(
        args["ephemeral_secret"],
        args["server_public"],
        args["timestamp"],
        args["short_id"],
    )
    return {"ephemeral_public": ephemeral_pub.hex(), "session_id": session_id.hex()}


def _parse_case(args: dict) -> dict:
    parsed = parse_client_hello(bytes.fromhex(args["client_hello"]))
    if parsed is None:
        return {"parsed": False, "session_id": None, "key_share": None}
    session_id, key_share = parsed
    return {
        "parsed": True,
        "session_id": session_id.hex(),
        "key_share": key_share.hex() if len(key_share) == 32 else None,
    }


def _public_key_case(args: dict) -> dict:
    return {"public_key": public_key_of(args["secret"]).hex()}


SERVER_SECRET = "22" * 32
SERVER_PUBLIC = public_key_of(SERVER_SECRET)

_HELLO_WITH_KEY_SHARE = build_client_hello(b"\xab" * 32, build_key_share_extension(b"\xcd" * 32))
_HELLO_WITHOUT_KEY_SHARE = build_client_hello(b"\xab" * 32, b"")
_HELLO_TWO_KEY_SHARES = build_client_hello(
    b"\xab" * 32,
    build_key_share_extension(b"\x11" * 32) + build_key_share_extension(b"\x22" * 32),
)
_HELLO_SECOND_KEY_SHARE_INVALID = build_client_hello(
    b"\xab" * 32,
    build_key_share_extension(b"\x11" * 32) + build_key_share_extension(b"\x22" * 31),
)
_HELLO_EMPTY_SESSION_ID = build_client_hello(b"", build_key_share_extension(b"\xcd" * 32))
_HELLO_P256_ONLY = build_client_hello(
    b"\xab" * 32,
    struct.pack(">HH", KEY_SHARE_EXTENSION, 71)
    + struct.pack(">H", 69)
    + struct.pack(">HH", 0x0017, 65)
    + b"\x04" * 65,
)

FUNCTIONS = [
    ParityFunction(
        name="public_key",
        python=_public_key_case,
        cases=[
            {"secret": SERVER_SECRET},
            {"secret": "11" * 32},
            {"secret": "00" * 32},
        ],
    ),
    ParityFunction(
        name="seal",
        python=_seal_case,
        cases=[
            {
                "ephemeral_secret": "11" * 32,
                "server_public": SERVER_PUBLIC.hex(),
                "timestamp": 1760000000,
                "short_id": "deadbeef",
            },
            {
                "ephemeral_secret": "33" * 32,
                "server_public": SERVER_PUBLIC.hex(),
                "timestamp": 0,
                "short_id": "00000000",
            },
            {
                "ephemeral_secret": "44" * 32,
                "server_public": SERVER_PUBLIC.hex(),
                "timestamp": 2147483647,
                "short_id": "ffffffff",
            },
            {
                "ephemeral_secret": "55" * 32,
                "server_public": SERVER_PUBLIC.hex(),
                "timestamp": -1,
                "short_id": "0a1b2c3d",
            },
        ],
    ),
    ParityFunction(
        name="parse_client_hello",
        python=_parse_case,
        cases=[
            {"client_hello": wrap_tls_record(_HELLO_WITH_KEY_SHARE).hex()},
            {"client_hello": _HELLO_WITH_KEY_SHARE.hex()},
            {"client_hello": wrap_tls_record(_HELLO_WITHOUT_KEY_SHARE).hex()},
            {"client_hello": wrap_tls_record(_HELLO_TWO_KEY_SHARES).hex()},
            {"client_hello": wrap_tls_record(_HELLO_SECOND_KEY_SHARE_INVALID).hex()},
            {"client_hello": wrap_tls_record(_HELLO_EMPTY_SESSION_ID).hex()},
            {"client_hello": wrap_tls_record(_HELLO_P256_ONLY).hex()},
            {"client_hello": ""},
            {"client_hello": "1603010004020000 00".replace(" ", "")},
            {"client_hello": "02000000"},
            {"client_hello": wrap_tls_record(_HELLO_WITH_KEY_SHARE)[:40].hex()},
            {"client_hello": wrap_tls_record(_HELLO_WITH_KEY_SHARE)[:44].hex()},
            {"client_hello": wrap_tls_record(_HELLO_WITH_KEY_SHARE)[:80].hex()},
        ],
    ),
]
