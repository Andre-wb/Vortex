"""Независимая Python-реализация форматов обфускации.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная по спецификации реализация, против которой сверяется
`vortex-transport`.

Конверт паддинга (`TrafficObfuscator.pad_message`) — формат прежний:

    конверт = real_len(2, big-endian) ‖ pad_len(2, big-endian) ‖ данные ‖ паддинг

но разбор строгий: длина конверта обязана совпасть с суммой полей, иначе это
не конверт. Сообщение или паддинг длиннее 65535 байт в формат не помещаются.

Кадр `vortex_obfs` — формат v2, несовместимый с v1 (в v1 полезная нагрузка
ехала открытым текстом под HMAC, кадр не был самоограничен и воспроизводился
бесконечно):

    ключ секрета   = HKDF-SHA256(ikm = секрет, salt = нет, "vortex-obfs-secret-v2", 32)
    пролог         = salt сеанса (16 случайных байт, шлёт инициатор)
    ключ данных    = HKDF-SHA256(ikm = ключ секрета, salt = salt, метка данных, 32)
    ключ длины     = HKDF-SHA256(ikm = ключ секрета, salt = salt, метка длины, 32)
    кадр           = wire_len(2) ‖ AES-256-GCM(plaintext)
    plaintext      = data_len(2, big-endian) ‖ данные ‖ паддинг
    body_len       = len(plaintext) + 16
    wire_len       = body_len ⊕ HMAC-SHA256(ключ длины, счётчик u64 BE)[:2]
    nonce          = счётчик u64 BE в младших восьми байтах двенадцати нулей
    AAD            = wire_len(2) ‖ счётчик u64 BE

Исход разбора кадра один из трёх: opened, need_more (данных ещё не хватает),
malformed (такой префикс кадром не станет никогда).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HEADER_LEN = 4
MAX_FIELD = 0xFFFF

SALT_LEN = 16
SECRET_INFO = b"vortex-obfs-secret-v2"
DATA_INITIATOR_LABEL = b"vortex-obfs data i2r v2"
DATA_RESPONDER_LABEL = b"vortex-obfs data r2i v2"
LENGTH_INITIATOR_LABEL = b"vortex-obfs len i2r v2"
LENGTH_RESPONDER_LABEL = b"vortex-obfs len r2i v2"

LENGTH_LEN = 2
DATA_LEN_LEN = 2
TAG_LEN = 16
NONCE_LEN = 12
MAX_PAYLOAD = 16384
MAX_PADDING = 1024
MIN_BODY = DATA_LEN_LEN + TAG_LEN
MAX_BODY = DATA_LEN_LEN + MAX_PAYLOAD + MAX_PADDING + TAG_LEN

OPENED = "opened"
NEED_MORE = "need_more"
MALFORMED = "malformed"

INITIATOR = "initiator"
RESPONDER = "responder"


def pad(data: bytes, padding: bytes) -> Optional[bytes]:
    """Конверт паддинга. Поле длиной больше двух байт формату не принадлежит."""
    if len(data) > MAX_FIELD or len(padding) > MAX_FIELD:
        return None
    header = len(data).to_bytes(2, "big") + len(padding).to_bytes(2, "big")
    return header + data + padding


def unpad(envelope: bytes) -> Optional[bytes]:
    """Разбор конверта. Длина обязана сойтись — иначе это не конверт."""
    if len(envelope) < HEADER_LEN:
        return None
    real_len = int.from_bytes(envelope[:2], "big")
    pad_len = int.from_bytes(envelope[2:4], "big")
    if HEADER_LEN + real_len + pad_len != len(envelope):
        return None
    return envelope[HEADER_LEN : HEADER_LEN + real_len]


def _hkdf(ikm: bytes, salt: Optional[bytes], info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def secret_key(secret: bytes) -> Optional[bytes]:
    """Ключ общего секрета. Пустой секрет — не секрет."""
    if not secret:
        return None
    return _hkdf(secret, None, SECRET_INFO)


def session_keys(secret: bytes, salt: bytes, role: str) -> Optional[dict]:
    key = secret_key(secret)
    if key is None or len(salt) != SALT_LEN:
        return None
    if role == INITIATOR:
        send_data, recv_data = DATA_INITIATOR_LABEL, DATA_RESPONDER_LABEL
        send_len, recv_len = LENGTH_INITIATOR_LABEL, LENGTH_RESPONDER_LABEL
    else:
        send_data, recv_data = DATA_RESPONDER_LABEL, DATA_INITIATOR_LABEL
        send_len, recv_len = LENGTH_RESPONDER_LABEL, LENGTH_INITIATOR_LABEL
    return {
        "send": _hkdf(key, salt, send_data),
        "recv": _hkdf(key, salt, recv_data),
        "send_length": _hkdf(key, salt, send_len),
        "recv_length": _hkdf(key, salt, recv_len),
    }


def _mask(length_key: bytes, counter: int) -> bytes:
    return hmac.new(length_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()[:LENGTH_LEN]


def _nonce(counter: int) -> bytes:
    return bytes(NONCE_LEN - 8) + counter.to_bytes(8, "big")


def _aad(wire_len: bytes, counter: int) -> bytes:
    return wire_len + counter.to_bytes(8, "big")


def seal_frame(keys: dict, counter: int, data: bytes, padding: bytes) -> Optional[bytes]:
    if len(data) > MAX_PAYLOAD or len(padding) > MAX_PADDING:
        return None
    plaintext = len(data).to_bytes(2, "big") + data + padding
    body_len = len(plaintext) + TAG_LEN
    wire_len = bytes(
        a ^ b for a, b in zip(body_len.to_bytes(2, "big"), _mask(keys["send_length"], counter), strict=True)
    )
    sealed = AESGCM(keys["send"]).encrypt(_nonce(counter), plaintext, _aad(wire_len, counter))
    return wire_len + sealed


def open_frame(keys: dict, counter: int, buffer: bytes) -> dict:
    if len(buffer) < LENGTH_LEN:
        return {"status": NEED_MORE, "consumed": 0, "data": None}
    wire_len = buffer[:LENGTH_LEN]
    body_len = int.from_bytes(
        bytes(a ^ b for a, b in zip(wire_len, _mask(keys["recv_length"], counter), strict=True)),
        "big",
    )
    if body_len < MIN_BODY or body_len > MAX_BODY:
        return {"status": MALFORMED, "consumed": 0, "data": None}
    frame_len = LENGTH_LEN + body_len
    if len(buffer) < frame_len:
        return {"status": NEED_MORE, "consumed": 0, "data": None}
    try:
        opened = AESGCM(keys["recv"]).decrypt(_nonce(counter), buffer[LENGTH_LEN:frame_len], _aad(wire_len, counter))
    except Exception:
        return {"status": MALFORMED, "consumed": 0, "data": None}
    if len(opened) < DATA_LEN_LEN:
        return {"status": MALFORMED, "consumed": 0, "data": None}
    data_len = int.from_bytes(opened[:DATA_LEN_LEN], "big")
    if DATA_LEN_LEN + data_len > len(opened):
        return {"status": MALFORMED, "consumed": 0, "data": None}
    return {
        "status": OPENED,
        "consumed": frame_len,
        "data": opened[DATA_LEN_LEN : DATA_LEN_LEN + data_len],
    }


def _pad_case(args: dict) -> dict:
    envelope = pad(bytes.fromhex(args["data"]), bytes.fromhex(args["padding"]))
    return {"envelope": None if envelope is None else envelope.hex()}


def _unpad_case(args: dict) -> dict:
    data = unpad(bytes.fromhex(args["envelope"]))
    return {"data": None if data is None else data.hex()}


def _seal_frames_case(args: dict) -> dict:
    keys = session_keys(bytes.fromhex(args["secret"]), bytes.fromhex(args["salt"]), args["role"])
    if keys is None:
        return {"frames": None}
    frames = []
    for counter, frame in enumerate(args["frames"]):
        sealed = seal_frame(keys, counter, bytes.fromhex(frame["data"]), bytes.fromhex(frame["padding"]))
        if sealed is None:
            return {"frames": None}
        frames.append(sealed.hex())
    return {"frames": frames}


def _open_frames_case(args: dict) -> dict:
    keys = session_keys(bytes.fromhex(args["secret"]), bytes.fromhex(args["salt"]), args["role"])
    if keys is None:
        return {"steps": None}
    steps = []
    counter = 0
    for buffer in args["buffers"]:
        step = open_frame(keys, counter, bytes.fromhex(buffer))
        if step["status"] == OPENED:
            counter += 1
        steps.append(
            {
                "status": step["status"],
                "consumed": step["consumed"],
                "data": None if step["data"] is None else step["data"].hex(),
            }
        )
    return {"steps": steps}


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list


SECRET = b"testsecret\n"
OTHER_SECRET = b"othersecret\x00"
SALT = b"\x11" * SALT_LEN
OTHER_SALT = b"\x12" * SALT_LEN


def _keys(secret: bytes = SECRET, salt: bytes = SALT, role: str = INITIATOR) -> dict:
    return session_keys(secret, salt, role)


_FIRST_FRAME = seal_frame(_keys(), 0, b"Hello, Vortex!", bytes(64)).hex()
_SECOND_FRAME = seal_frame(_keys(), 1, b"second", bytes(64)).hex()
_EMPTY_FRAME = seal_frame(_keys(), 0, b"", bytes(64)).hex()
_STRANGER_FRAME = seal_frame(_keys(secret=OTHER_SECRET), 0, b"body", bytes(64)).hex()
_OTHER_SALT_FRAME = seal_frame(_keys(salt=OTHER_SALT), 0, b"body", bytes(64)).hex()
_RESPONDER_FRAME = seal_frame(_keys(role=RESPONDER), 0, b"back", bytes(64)).hex()
_TAMPERED_FRAME = (_FIRST_FRAME[:-2] + ("00" if _FIRST_FRAME[-2:] != "00" else "01")).lower()

FUNCTIONS: list[ParityFunction] = [
    ParityFunction(
        name="pad",
        python=_pad_case,
        cases=[
            {"data": "", "padding": "00" * 16},
            {"data": "48656c6c6f2c20566f7274657821", "padding": "00" * 40},
            {"data": "48656c6c6f2c20566f7274657821", "padding": ""},
            {"data": "ff" * 255, "padding": "aa" * 512},
        ],
    ),
    ParityFunction(
        name="unpad",
        python=_unpad_case,
        cases=[
            {"envelope": pad(b"", bytes(16)).hex()},
            {"envelope": pad(b"Hello, Vortex!", bytes(40)).hex()},
            {"envelope": pad(b"Hello, Vortex!", b"").hex()},
            {"envelope": pad(b"body", bytes(16)).hex()[:-2]},
            {"envelope": pad(b"body", bytes(16)).hex() + "00"},
            {"envelope": "0001"},
            {"envelope": ""},
            {"envelope": "00040000" + "41" * 4},
            {"envelope": "0004ffff" + "41" * 4},
        ],
    ),
    ParityFunction(
        name="seal_frames",
        python=_seal_frames_case,
        cases=[
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "48656c6c6f2c20566f7274657821", "padding": "00" * 64}],
            },
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [
                    {"data": "48656c6c6f2c20566f7274657821", "padding": "00" * 64},
                    {"data": "7365636f6e64", "padding": "00" * 64},
                    {"data": "7468697264", "padding": "ff" * 512},
                ],
            },
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": RESPONDER,
                "frames": [{"data": "6261636b", "padding": "00" * 64}],
            },
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "", "padding": "00" * 64}],
            },
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "41" * 16, "padding": ""}],
            },
            {
                "secret": SECRET.hex(),
                "salt": OTHER_SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "626f6479", "padding": "00" * 64}],
            },
            {
                "secret": OTHER_SECRET.hex(),
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "626f6479", "padding": "00" * 64}],
            },
            {
                "secret": "",
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "626f6479", "padding": "00" * 64}],
            },
            {
                "secret": SECRET.hex(),
                "salt": (b"\x11" * (SALT_LEN - 1)).hex(),
                "role": INITIATOR,
                "frames": [{"data": "626f6479", "padding": "00" * 64}],
            },
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": INITIATOR,
                "frames": [{"data": "626f6479", "padding": "00" * (MAX_PADDING + 1)}],
            },
        ],
    ),
    ParityFunction(
        name="open_frames",
        python=_open_frames_case,
        cases=[
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_FIRST_FRAME]},
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": RESPONDER,
                "buffers": [_FIRST_FRAME, _SECOND_FRAME],
            },
            {
                "secret": SECRET.hex(),
                "salt": SALT.hex(),
                "role": RESPONDER,
                "buffers": [_FIRST_FRAME, _FIRST_FRAME],
            },
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_SECOND_FRAME]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_EMPTY_FRAME]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": INITIATOR, "buffers": [_RESPONDER_FRAME]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_STRANGER_FRAME]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_OTHER_SALT_FRAME]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_TAMPERED_FRAME]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [""]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_FIRST_FRAME[:2]]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_FIRST_FRAME[:-2]]},
            {"secret": SECRET.hex(), "salt": SALT.hex(), "role": RESPONDER, "buffers": [_FIRST_FRAME + "41"]},
            {"secret": "", "salt": SALT.hex(), "role": RESPONDER, "buffers": [_FIRST_FRAME]},
            {
                "secret": SECRET.hex(),
                "salt": (b"\x11" * (SALT_LEN + 1)).hex(),
                "role": RESPONDER,
                "buffers": [_FIRST_FRAME],
            },
        ],
    ),
]
