"""Кросс-языковые golden-тесты UDP-обнаружения: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/net_parity.json` (генератор
`scripts/gen_net_parity_vectors.py`), вторая независимая реализация формата —
`app/tests/net_parity_reference.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import net_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "net_parity.json"

try:
    import vortex_chat as _rust
except ImportError:
    _rust = None

requires_rust = pytest.mark.skipif(_rust is None, reason="vortex_chat не собран")


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _cases():
    vectors = _vectors()
    for fn in reference.FUNCTIONS:
        for index, vector in enumerate(vectors[fn.name]):
            yield pytest.param(fn, vector, id=f"{fn.name}-{index}")


ALL_CASES = list(_cases())


class TestVectorFile:
    def test_covers_every_function(self):
        assert set(_vectors()) == {fn.name for fn in reference.FUNCTIONS}

    def test_case_count_matches_reference(self):
        vectors = _vectors()
        for fn in reference.FUNCTIONS:
            assert len(vectors[fn.name]) == len(fn.cases), fn.name

    def test_frozen_args_match_reference(self):
        vectors = _vectors()
        for fn in reference.FUNCTIONS:
            frozen = [v["args"] for v in vectors[fn.name]]
            assert frozen == [json.loads(json.dumps(c)) for c in fn.cases], fn.name


@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


def _rust_encode(args: dict) -> dict:
    frame = _rust.udp_encode(args["name"], args["port"], args.get("pubkey"))
    return {"frame": bytes(frame).hex()}


def _rust_decode(args: dict):
    result = _rust.udp_decode(bytes.fromhex(args["frame"]), args["fallback_name"], args["fallback_port"])
    if result is None:
        return None
    name, port, pubkey = result
    return {"name": name, "port": port, "pubkey": pubkey}


def _rust_seal(args: dict) -> dict:
    sealed = _rust.udp_stealth_seal(
        bytes.fromhex(args["payload"]),
        bytes.fromhex(args["network_key"]),
        bytes.fromhex(args["nonce"]),
    )
    return {"sealed": bytes(sealed).hex()}


def _rust_open(args: dict):
    opened = _rust.udp_stealth_open(bytes.fromhex(args["data"]), bytes.fromhex(args["network_key"]))
    return None if opened is None else {"opened": bytes(opened).hex()}


def _rust_subnet(args: dict) -> dict:
    return {"broadcast": _rust.udp_subnet_broadcast(args["ip"])}


RUST_IMPLEMENTATIONS = {
    "encode": _rust_encode,
    "decode": _rust_decode,
    "stealth_seal": _rust_seal,
    "stealth_open": _rust_open,
    "subnet_broadcast": _rust_subnet,
}


@requires_rust
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


class TestEnvelopeFormat:
    def test_a_sealed_envelope_is_the_nonce_followed_by_the_payload_length(self):
        for vector in _vectors()["stealth_seal"]:
            payload_len = len(bytes.fromhex(vector["args"]["payload"]))
            sealed_len = len(bytes.fromhex(vector["expected"]["sealed"]))
            assert sealed_len == reference.STEALTH_NONCE_LEN + payload_len

    def test_encode_omits_the_pubkey_field_when_it_is_absent(self):
        keyless = reference.encode("solo", 9000, None)
        assert b"pubkey" not in keyless
        keyed = reference.encode("solo", 9000, "aa" * 32)
        assert b"pubkey" in keyed

    def test_every_encoded_frame_decodes_back_to_its_inputs(self):
        for vector in _vectors()["encode"]:
            args = vector["args"]
            frame = bytes.fromhex(vector["expected"]["frame"])
            decoded = reference.decode(frame, "0.0.0.0", 1)
            assert decoded is not None
            assert decoded["name"] == "".join(list(args["name"])[: reference.NAME_MAX_CHARS])
            assert decoded["port"] == args["port"]


@requires_rust
class TestCrossRuntime:
    PUBKEY = "cd" * 32
    NETWORK_KEY = b"cross-runtime-network-key"
    NONCE = b"\x09" * 8

    def test_rust_decodes_a_frame_python_encoded(self):
        frame = reference.encode("crossnode", 9000, self.PUBKEY)
        assert _rust.udp_decode(frame, "1.2.3.4", 8000) == ("crossnode", 9000, self.PUBKEY)

    def test_python_decodes_a_frame_rust_encoded(self):
        frame = bytes(_rust.udp_encode("crossnode", 9000, self.PUBKEY))
        assert reference.decode(frame, "1.2.3.4", 8000) == {
            "name": "crossnode",
            "port": 9000,
            "pubkey": self.PUBKEY,
        }

    def test_rust_opens_what_python_sealed(self):
        sealed = reference.stealth_seal(b"payload-xyz", self.NETWORK_KEY, self.NONCE)
        assert bytes(_rust.udp_stealth_open(sealed, self.NETWORK_KEY)) == b"payload-xyz"

    def test_python_opens_what_rust_sealed(self):
        sealed = bytes(_rust.udp_stealth_seal(b"payload-xyz", self.NETWORK_KEY, self.NONCE))
        assert reference.stealth_open(sealed, self.NETWORK_KEY) == b"payload-xyz"
