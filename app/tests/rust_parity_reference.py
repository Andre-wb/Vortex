"""Эталонные Python-реализации функций, продублированных в Rust (`vortex_chat`).

Только stdlib и без импорта `app.*`: шимы приложения переключаются на Rust,
эталон обязан оставаться независимым.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import blake3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BMP_ROTATION_PERIOD = 3600
BMP_ROTATION_JITTER = 600
BMP_CLOCK_SKEW_EPOCHS = 1
BMP_TIMESTAMP_BUCKET = 300

PAD_BUCKETS = (64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

RATCHET_INFO = b"vortex-double-ratchet"
CHAIN_LABEL = b"\x02"
MSG_KEY_LABEL = b"\x01"


@dataclass(frozen=True)
class ParityFn:
    """Одна функция, продублированная в Rust, с набором замороженных входов."""

    name: str
    cases: tuple[dict[str, Any], ...]
    python: Callable[[dict[str, Any]], Any]
    rust: Callable[[Any, dict[str, Any]], Any]


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _det(label: str, size: int = 32) -> str:
    return hashlib.sha256(f"vortex-parity:{label}".encode()).digest()[:size].hex()


def _py_hash_message(case: dict[str, Any]) -> str:
    return blake3.blake3(_b(case["data_hex"])).digest().hex()


def _py_hash_token(case: dict[str, Any]) -> str:
    return hashlib.sha256(case["token"].encode("utf-8")).hexdigest()


def _py_sender_pseudo(case: dict[str, Any]) -> str:
    data = case["room_id"].to_bytes(8, "big", signed=True)
    data += case["user_id"].to_bytes(8, "big", signed=True)
    return hashlib.blake2b(data, key=_b(case["secret_hex"]), digest_size=32).hexdigest()


def _py_canonical_json(case: dict[str, Any]) -> str:
    dumped = json.dumps(case["obj"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return dumped.encode("utf-8").hex()


def _py_kdf_rk(case: dict[str, Any]) -> list[str]:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=_b(case["rk_hex"]),
        info=RATCHET_INFO,
    ).derive(_b(case["dh_hex"]))
    return [okm[:32].hex(), okm[32:].hex()]


def _py_kdf_ck(case: dict[str, Any]) -> list[str]:
    ck = _b(case["ck_hex"])
    new_ck = hmac.new(ck, CHAIN_LABEL, hashlib.sha256).digest()
    mk = hmac.new(ck, MSG_KEY_LABEL, hashlib.sha256).digest()
    return [new_ck.hex(), mk.hex()]


def _py_advance_chain(case: dict[str, Any]) -> str:
    return hmac.new(_b(case["ck_hex"]), CHAIN_LABEL, hashlib.sha256).hexdigest()


def _py_message_key(case: dict[str, Any]) -> str:
    return hmac.new(_b(case["ck_hex"]), MSG_KEY_LABEL, hashlib.sha256).hexdigest()


def _py_root_kdf(case: dict[str, Any]) -> str:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_b(case["info_hex"]),
    ).derive(_b(case["shared_secret_hex"]))
    return okm.hex()


def _py_sha256_hex(case: dict[str, Any]) -> str:
    return hashlib.sha256(_b(case["data_hex"])).hexdigest()


def _py_sha256_concat_hex(case: dict[str, Any]) -> list[str]:
    return [hashlib.sha256(_b(c)).hexdigest() for c in case["chunks_hex"]]


def _py_sha256_combine_hex(case: dict[str, Any]) -> str:
    return hashlib.sha256("".join(case["hex_list"]).encode("utf-8")).hexdigest()


def _py_sha256_stream(case: dict[str, Any]) -> list[Any]:
    raw = _b(case["data_hex"])
    return [hashlib.sha256(raw).hexdigest(), len(raw)]


def _pair_jitter(secret_hex: str) -> int:
    sig = hmac.new(_b(secret_hex), b"jitter", hashlib.sha256).digest()
    return ((sig[0] << 8) | sig[1]) % BMP_ROTATION_JITTER


def _mailbox_for_epoch(secret_hex: str, epoch: int) -> str:
    sig = hmac.new(_b(secret_hex), epoch.to_bytes(8, "big"), hashlib.sha256).digest()
    return sig[:16].hex()


def _py_pair_jitter(case: dict[str, Any]) -> int:
    return _pair_jitter(case["secret_hex"])


def _py_mailbox_id(case: dict[str, Any]) -> str:
    adjusted = case["timestamp"] - _pair_jitter(case["secret_hex"])
    return _mailbox_for_epoch(case["secret_hex"], max(0, int(adjusted / BMP_ROTATION_PERIOD)))


def _py_mailbox_ids(case: dict[str, Any]) -> list[str]:
    adjusted = case["timestamp"] - _pair_jitter(case["secret_hex"])
    epoch = int(adjusted / BMP_ROTATION_PERIOD)
    span = range(epoch - BMP_CLOCK_SKEW_EPOCHS, epoch + BMP_CLOCK_SKEW_EPOCHS + 1)
    return [_mailbox_for_epoch(case["secret_hex"], max(0, e)) for e in span]


def _py_wake_category(case: dict[str, Any]) -> int:
    return hashlib.sha256(case["mailbox_id"].encode()).digest()[0]


def _py_bucket_timestamp(case: dict[str, Any]) -> float:
    ts = case["timestamp"]
    if ts <= 0:
        return 0.0
    return float(int(ts) // BMP_TIMESTAMP_BUCKET * BMP_TIMESTAMP_BUCKET)


def _py_pad_bucket_for(case: dict[str, Any]) -> int:
    needed = case["length"] + 2
    return next((b for b in PAD_BUCKETS if b >= needed), 65536)


def signing_key(seed_hex: str) -> Ed25519PrivateKey:
    """Детерминированный Ed25519-ключ: подпись RFC 8032 воспроизводима."""
    return Ed25519PrivateKey.from_private_bytes(_b(seed_hex))


def signature_inputs(case: dict[str, Any]) -> tuple[bytes, bytes, bytes]:
    """Возвращает (pubkey, message, signature) для случая проверки подписи."""
    key = signing_key(case["seed_hex"])
    message = _b(case["message_hex"])
    signature = key.sign(message)
    if case["tampered"]:
        message = message + b"\x00"
    return key.public_key().public_bytes_raw(), message, signature


def _py_ed25519_verify(case: dict[str, Any]) -> bool:
    return not case["tampered"]


def _rust_ed25519_verify(module: Any, case: dict[str, Any]) -> bool:
    pubkey, message, signature = signature_inputs(case)
    return module.verify_signature(pubkey, message, signature)


FUNCTIONS: tuple[ParityFn, ...] = (
    ParityFn(
        name="hash_message",
        cases=(
            {"data_hex": ""},
            {"data_hex": "00"},
            {"data_hex": _det("blake3-a", 32)},
            {"data_hex": bytes(range(256)).hex()},
        ),
        python=_py_hash_message,
        rust=lambda m, c: m.hash_message(_b(c["data_hex"])).hex(),
    ),
    ParityFn(
        name="hash_token",
        cases=(
            {"token": ""},
            {"token": "vortex-session-token"},
            {"token": "токен-с-юникодом-🔒"},
        ),
        python=_py_hash_token,
        rust=lambda m, c: m.hash_token(c["token"]),
    ),
    ParityFn(
        name="compute_sender_pseudo",
        cases=(
            {"secret_hex": _det("pseudo-secret"), "room_id": 0, "user_id": 0},
            {"secret_hex": _det("pseudo-secret"), "room_id": 1, "user_id": 2},
            {"secret_hex": _det("pseudo-secret"), "room_id": -5, "user_id": 9223372036854775807},
            {"secret_hex": _det("pseudo-secret"), "room_id": -9223372036854775808, "user_id": -1},
        ),
        python=_py_sender_pseudo,
        rust=lambda m, c: m.compute_sender_pseudo(_b(c["secret_hex"]), c["room_id"], c["user_id"]),
    ),
    ParityFn(
        name="canonical_json",
        cases=(
            {"obj": {"b": 1, "a": "x"}},
            {"obj": {"a": "привет", "b": [1, 2, {"c": None}]}},
            {"obj": {"z": True, "y": False, "x": None}},
            {"obj": {"name": "Мой узел", "mode": "global", "ai_capable": False}},
            {"obj": {"s": 'line\nbreak\ttab"quote\\back'}},
            {"obj": {"s": ""}},
            {"obj": {"emoji": "🔒"}},
            {"obj": {"f": 0.5}},
            {"obj": {"f": 123456789.125}},
            {"obj": {"i": 4611686018427387904}},
            {"obj": []},
            {"obj": {}},
            {"obj": "plain"},
            {"obj": 123},
        ),
        python=_py_canonical_json,
        rust=lambda m, c: m.canonical_json(c["obj"]).hex(),
    ),
    ParityFn(
        name="ratchet_kdf_rk",
        cases=(
            {"rk_hex": _det("rk-a"), "dh_hex": _det("dh-a")},
            {"rk_hex": "00" * 32, "dh_hex": "ff" * 32},
        ),
        python=_py_kdf_rk,
        rust=lambda m, c: [x.hex() for x in m.ratchet_kdf_rk(_b(c["rk_hex"]), _b(c["dh_hex"]))],
    ),
    ParityFn(
        name="ratchet_kdf_ck",
        cases=({"ck_hex": _det("ck-a")}, {"ck_hex": "00" * 32}),
        python=_py_kdf_ck,
        rust=lambda m, c: [x.hex() for x in m.ratchet_kdf_ck(_b(c["ck_hex"]))],
    ),
    ParityFn(
        name="ratchet_advance_chain",
        cases=({"ck_hex": _det("ck-a")}, {"ck_hex": "ff" * 32}),
        python=_py_advance_chain,
        rust=lambda m, c: m.ratchet_advance_chain(_b(c["ck_hex"])).hex(),
    ),
    ParityFn(
        name="ratchet_message_key",
        cases=({"ck_hex": _det("ck-a")}, {"ck_hex": "ff" * 32}),
        python=_py_message_key,
        rust=lambda m, c: m.ratchet_message_key(_b(c["ck_hex"])).hex(),
    ),
    ParityFn(
        name="ratchet_root_kdf",
        cases=(
            {"shared_secret_hex": _det("ss-a"), "info_hex": b"vortex-info".hex()},
            {"shared_secret_hex": _det("ss-b"), "info_hex": ""},
        ),
        python=_py_root_kdf,
        rust=lambda m, c: m.ratchet_root_kdf(_b(c["shared_secret_hex"]), _b(c["info_hex"])).hex(),
    ),
    ParityFn(
        name="sha256_hex",
        cases=(
            {"data_hex": ""},
            {"data_hex": bytes(range(256)).hex()},
        ),
        python=_py_sha256_hex,
        rust=lambda m, c: m.sha256_hex(_b(c["data_hex"])),
    ),
    ParityFn(
        name="sha256_concat_hex",
        cases=({"chunks_hex": ["", "61", bytes(range(64)).hex()]},),
        python=_py_sha256_concat_hex,
        rust=lambda m, c: m.sha256_concat_hex([_b(x) for x in c["chunks_hex"]]),
    ),
    ParityFn(
        name="sha256_combine_hex",
        cases=(
            {"hex_list": [hashlib.sha256(bytes([i])).hexdigest() for i in range(4)]},
            {"hex_list": []},
        ),
        python=_py_sha256_combine_hex,
        rust=lambda m, c: m.sha256_combine_hex(c["hex_list"]),
    ),
    ParityFn(
        name="sha256_stream",
        cases=({"data_hex": ""}, {"data_hex": bytes(range(128)).hex()}),
        python=_py_sha256_stream,
        rust=lambda m, c: list(m.sha256_stream(_b(c["data_hex"]))),
    ),
    ParityFn(
        name="bmp_pair_jitter",
        cases=(
            {"secret_hex": "ab" * 32},
            {"secret_hex": "cd" * 32},
            {"secret_hex": _det("bmp")},
            {"secret_hex": "00" * 32},
            {"secret_hex": "ff" * 32},
        ),
        python=_py_pair_jitter,
        rust=lambda m, c: m.bmp_pair_jitter(c["secret_hex"]),
    ),
    ParityFn(
        name="bmp_compute_mailbox_id",
        cases=(
            {"secret_hex": "ab" * 32, "timestamp": 1700000000.0},
            {"secret_hex": "cd" * 32, "timestamp": 1700003600.5},
            {"secret_hex": _det("bmp"), "timestamp": 1.0},
            {"secret_hex": "ab" * 32, "timestamp": 0.0},
            {"secret_hex": "ab" * 32, "timestamp": 3599.999},
            {"secret_hex": "ab" * 32, "timestamp": 4200.0},
            {"secret_hex": "ff" * 32, "timestamp": 599.0},
            {"secret_hex": _det("bmp"), "timestamp": 4102444800.0},
        ),
        python=_py_mailbox_id,
        rust=lambda m, c: m.bmp_compute_mailbox_id(c["secret_hex"], c["timestamp"]),
    ),
    ParityFn(
        name="bmp_compute_mailbox_ids",
        cases=(
            {"secret_hex": "ab" * 32, "timestamp": 1700000000.0},
            {"secret_hex": _det("bmp"), "timestamp": 1.0},
            {"secret_hex": "ab" * 32, "timestamp": 0.0},
            {"secret_hex": "cd" * 32, "timestamp": 3600.0},
            {"secret_hex": "ff" * 32, "timestamp": 599.0},
            {"secret_hex": _det("bmp"), "timestamp": 4102444800.0},
        ),
        python=_py_mailbox_ids,
        rust=lambda m, c: m.bmp_compute_mailbox_ids(c["secret_hex"], c["timestamp"]),
    ),
    ParityFn(
        name="bmp_wake_category",
        cases=(
            {"mailbox_id": "0123456789abcdef"},
            {"mailbox_id": _det("bmp-mailbox", 16)},
            {"mailbox_id": "ff" * 32},
            {"mailbox_id": "00" * 8},
        ),
        python=_py_wake_category,
        rust=lambda m, c: m.bmp_wake_category(c["mailbox_id"]),
    ),
    ParityFn(
        name="bmp_bucket_timestamp",
        cases=tuple(
            {"timestamp": ts}
            for ts in (0.0, 1.0, 299.999, 300.0, 1700000000.0, 1700000299.0, 1700000300.0)
        ),
        python=_py_bucket_timestamp,
        rust=lambda m, c: m.bmp_bucket_timestamp(c["timestamp"]),
    ),
    ParityFn(
        name="pad_bucket_for",
        cases=tuple({"length": n} for n in (0, 1, 62, 63, 100, 1000, 4094, 65533)),
        python=_py_pad_bucket_for,
        rust=lambda m, c: m.pad_bucket_for(c["length"]),
    ),
    ParityFn(
        name="ed25519_verify",
        cases=(
            {"seed_hex": _det("ed-a"), "message_hex": b"parity-message".hex(), "tampered": False},
            {"seed_hex": _det("ed-a"), "message_hex": b"parity-message".hex(), "tampered": True},
            {"seed_hex": _det("ed-b"), "message_hex": "", "tampered": False},
        ),
        python=_py_ed25519_verify,
        rust=_rust_ed25519_verify,
    ),
)
