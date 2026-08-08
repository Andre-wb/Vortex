"""Кросс-языковые golden-тесты Trojan: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/trojan_parity.json` (генератор
`scripts/gen_trojan_parity_vectors.py`), вторая независимая реализация
формата — `app/tests/trojan_parity_reference.py`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.tests import trojan_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "trojan_parity.json"

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


@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


def _guard(passwords: list[str]):
    guard = _rust.Trojan(passwords[0] if passwords else "")
    for extra in passwords[1:]:
        guard.add_password(extra)
    return guard


def _rust_password_hash(args: dict) -> dict:
    return {"hash": _rust.Trojan(args["password"]).password_hash}


def _rust_encode_request(args: dict) -> dict:
    request = _rust.Trojan(args["password"]).encode_request(
        bytes.fromhex(args["payload"]), args["host"], args["port"]
    )
    return {"request": request.hex()}


def _rust_decode_request(args: dict) -> dict:
    guard = _guard(args["passwords"])
    data = bytes.fromhex(args["data"])
    outcome = guard.inspect(data)
    request = guard.decode_request(data)
    if request is None:
        return {
            "outcome": outcome,
            "password_hash": None,
            "command": None,
            "address_type": None,
            "host": None,
            "port": None,
            "payload": None,
        }
    return {
        "outcome": outcome,
        "password_hash": request.password_hash,
        "command": request.command,
        "address_type": request.address_type,
        "host": request.host,
        "port": request.port,
        "payload": request.payload.hex(),
    }


def _rust_probe(args: dict) -> dict:
    return {"probe": _rust.Trojan("testpass").probe(bytes.fromhex(args["data"]))}


RUST_IMPLEMENTATIONS = {
    "password_hash": _rust_password_hash,
    "encode_request": _rust_encode_request,
    "decode_request": _rust_decode_request,
    "probe": _rust_probe,
}


@requires_rust
@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


@pytest.mark.crypto
class TestRequestFormat:
    def test_the_hash_field_is_fifty_six_hex_digits_and_a_crlf(self):
        for vector in _vectors()["encode_request"]:
            request = bytes.fromhex(vector["expected"]["request"])
            assert len(request[: reference.PASSWORD_HASH_HEX_LEN]) == 56
            assert bytes(request[56:58]) == b"\r\n"

    def test_the_wire_format_is_the_published_one_and_did_not_change(self):
        request = reference.encode_request(b"testpass", "13.10.1.2", 443, b"hi")
        assert request[:56] == reference.password_hash(b"testpass").encode()
        assert request[56:] == b"\r\n\x01\x01\x0d\x0a\x01\x02\x01\xbb\r\nhi"

    def test_a_crlf_inside_the_header_is_not_the_end_of_the_header(self):
        request = reference.encode_request(b"testpass", "13.10.13.10", 3338, b"payload")
        body = request[reference.HASH_FIELD_LEN :]
        assert body.count(b"\r\n") > 1
        decoded = reference.decode_request([b"testpass"], request)
        assert decoded["host"] == "13.10.13.10"
        assert decoded["port"] == 3338
        assert bytes.fromhex(decoded["payload"]) == b"payload"


@requires_rust
@pytest.mark.crypto
class TestCrossRuntimeRequest:
    PASSWORD = reference.PASSWORD.decode()

    @pytest.mark.parametrize(
        "host,port",
        [
            ("www.example.com", 443),
            ("13.10.13.10", 80),
            ("www.example.com", 3338),
            ("13.10.1.2", 3338),
            ("2001:db8::1", 443),
        ],
    )
    def test_rust_decodes_what_python_encoded(self, host, port):
        data = reference.encode_request(reference.PASSWORD, host, port, b"payload")
        request = _rust.Trojan(self.PASSWORD).decode_request(data)
        assert request is not None
        assert request.host == host
        assert request.port == port
        assert request.payload == b"payload"

    @pytest.mark.parametrize(
        "host,port",
        [
            ("www.example.com", 443),
            ("13.10.13.10", 80),
            ("www.example.com", 3338),
            ("2001:db8::1", 443),
        ],
    )
    def test_python_decodes_what_rust_encoded(self, host, port):
        data = _rust.Trojan(self.PASSWORD).encode_request(b"payload", host, port)
        decoded = reference.decode_request([reference.PASSWORD], data)
        assert decoded["outcome"] == "accepted"
        assert decoded["host"] == host
        assert decoded["port"] == port
        assert bytes.fromhex(decoded["payload"]) == b"payload"

    def test_a_client_that_shouts_its_hash_in_uppercase_is_still_authorized(self):
        data = bytearray(reference.encode_request(reference.PASSWORD, "13.10.1.2", 443, b""))
        data[:56] = data[:56].upper()
        request = _rust.Trojan(self.PASSWORD).decode_request(bytes(data))
        assert request is not None
        assert request.password_hash == reference.password_hash(reference.PASSWORD)

    def test_the_previous_password_is_still_accepted(self):
        guard = _rust.Trojan("newpass", self.PASSWORD)
        data = reference.encode_request(reference.PASSWORD, "13.10.1.2", 443, b"")
        assert guard.decode_request(data) is not None

    def test_an_added_password_survives_a_rotation(self):
        guard = _rust.Trojan("newpass")
        guard.add_password(self.PASSWORD)
        guard.reload("newest", "newpass")
        data = reference.encode_request(reference.PASSWORD, "13.10.1.2", 443, b"")
        assert guard.decode_request(data) is not None

    def test_an_unknown_password_is_unauthorized_and_not_malformed(self):
        data = reference.encode_request(b"nobody knows this", "13.10.1.2", 443, b"")
        guard = _rust.Trojan(self.PASSWORD)
        assert guard.inspect(data) == "unauthorized"
        assert guard.decode_request(data) is None


@requires_rust
@pytest.mark.crypto
class TestStreamingBoundary:
    PASSWORD = reference.PASSWORD.decode()

    def test_a_request_arriving_byte_by_byte_asks_for_more_until_it_is_whole(self):
        guard = _rust.Trojan(self.PASSWORD)
        data = reference.encode_request(reference.PASSWORD, "www.example.com", 443, b"")
        for cut in range(len(data)):
            assert guard.inspect(data[:cut]) == "need_more", cut
        assert guard.inspect(data) == "accepted"

    def test_nothing_incomplete_is_longer_than_the_biggest_possible_header(self):
        guard = _rust.Trojan(self.PASSWORD)
        longest = reference.encode_request(reference.PASSWORD, "a" * 253, 443, b"")
        assert len(longest) <= guard.max_request_header_len
        assert guard.inspect(longest[:-1]) == "need_more"
        assert guard.inspect(longest) == "accepted"

    def test_a_prefix_that_can_never_become_a_request_is_refused_at_once(self):
        guard = _rust.Trojan(self.PASSWORD)
        for data in [b"GET / HTTP/1.1\r\n", bytes.fromhex("16030100050100000d"), b"zz"]:
            assert guard.inspect(data) == "malformed"
            assert guard.probe(data) == "not_trojan"

    def test_an_empty_password_authenticates_nobody(self):
        guard = _rust.Trojan("")
        assert not guard.is_configured
        assert guard.password_hash is None
        forged = hashlib.sha224(b"").hexdigest().encode() + b"\r\n\x01\x01\x0d\x0a\x01\x02\x01\xbb\r\n"
        assert guard.inspect(forged) == "unauthorized"
