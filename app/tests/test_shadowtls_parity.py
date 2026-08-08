"""Кросс-языковые golden-тесты ShadowTLS: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/shadowtls_parity.json` (генератор
`scripts/gen_shadowtls_parity_vectors.py`), вторая независимая реализация
формата — `app/tests/shadowtls_parity_reference.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import shadowtls_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "shadowtls_parity.json"

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


def _guard(password: str):
    return _rust.ShadowTls(password)


def _rust_switch_token(args: dict) -> dict:
    record = _guard(args["password"]).seal_switch_derand(
        bytes.fromhex(args["server_random"]), bytes.fromhex(args["session_id"]), b""
    )
    body = record[reference.RECORD_HEADER_LEN :]
    return {"token": body[reference.SESSION_ID_LEN : reference.SWITCH_PREFIX_LEN].hex()}


def _rust_switch_record(args: dict) -> dict:
    record = _guard(args["password"]).seal_switch_derand(
        bytes.fromhex(args["server_random"]),
        bytes.fromhex(args["session_id"]),
        bytes.fromhex(args["padding"]),
    )
    return {"record": record.hex()}


def _rust_wrap(args: dict) -> dict:
    stream = _guard(args["password"]).stream(
        bytes.fromhex(args["server_random"]), bytes.fromhex(args["session_id"]), args["server"]
    )
    return {"frames": [stream.wrap(bytes.fromhex(message)).hex() for message in args["messages"]]}


def _rust_server_random(args: dict) -> dict:
    found = _rust.ShadowTls.parse_server_random(bytes.fromhex(args["data"]))
    return {"server_random": found.hex() if found is not None else None}


def _rust_server_name(args: dict) -> dict:
    return {"host": _rust.ShadowTls.parse_server_name(bytes.fromhex(args["data"]))}


def _rust_split_records(args: dict) -> dict:
    records, leftover, opaque = _rust.ShadowTls.split_records(bytes.fromhex(args["data"]))
    return {
        "records": [bytes(item).hex() for item in records],
        "leftover": bytes(leftover).hex(),
        "opaque": opaque,
    }


RUST_IMPLEMENTATIONS = {
    "switch_token": _rust_switch_token,
    "switch_record": _rust_switch_record,
    "wrap": _rust_wrap,
    "server_random": _rust_server_random,
    "server_name": _rust_server_name,
    "split_records": _rust_split_records,
}


@requires_rust
@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


@pytest.mark.crypto
class TestSwitchRecordFormat:
    def test_the_session_id_travels_in_the_clear_in_front_of_the_marker(self):
        for vector in _vectors()["switch_record"]:
            body = bytes.fromhex(vector["expected"]["record"])[reference.RECORD_HEADER_LEN :]
            assert body[: reference.SESSION_ID_LEN].hex() == vector["args"]["session_id"]

    def test_the_donor_random_alone_changes_the_marker(self):
        tokens = _vectors()["switch_token"]
        same_password = [v for v in tokens if v["args"]["password"] == reference.PASSWORD.decode()]
        markers = {v["expected"]["token"] for v in same_password}
        assert len(markers) == len(same_password)

    def test_every_record_declares_its_own_length(self):
        for vector in _vectors()["switch_record"]:
            record = bytes.fromhex(vector["expected"]["record"])
            assert record[:3] == b"\x17\x03\x03"
            assert int.from_bytes(record[3:5], "big") == len(record) - reference.RECORD_HEADER_LEN


@requires_rust
@pytest.mark.crypto
class TestCrossRuntimeSwitch:
    PASSWORD = reference.PASSWORD.decode()
    SERVER_RANDOM = reference.SERVER_RANDOM
    SESSION_ID = reference.SESSION_ID

    def _switched(self, guard, switch: bytes, server_random: bytes | None = None):
        connection = guard.connection()
        connection.feed_client(
            reference.wrap_handshake(
                reference.build_client_hello(bytes(32), reference.build_server_name_extension(b"www.google.com"))
            )
        )
        connection.feed_donor(
            reference.wrap_handshake(reference.build_server_hello(server_random or self.SERVER_RANDOM))
        )
        return connection, connection.feed_client(switch)

    def test_rust_accepts_a_switch_sealed_by_python(self):
        guard = _rust.ShadowTls(self.PASSWORD)
        switch = reference.switch_record(
            self.PASSWORD.encode(), self.SERVER_RANDOM, self.SESSION_ID, bytes(200)
        )
        _, step = self._switched(guard, switch)
        assert step.session_id == self.SESSION_ID
        assert step.forward == b""

    def test_python_verifies_a_switch_sealed_by_rust(self):
        guard = _rust.ShadowTls(self.PASSWORD)
        record = guard.seal_switch(self.SERVER_RANDOM, self.SESSION_ID)
        found = reference.match_switch_record(
            [self.PASSWORD.encode()], self.SERVER_RANDOM, record[0], record[reference.RECORD_HEADER_LEN :]
        )
        assert found == self.SESSION_ID

    def test_a_switch_captured_from_another_connection_is_refused(self):
        guard = _rust.ShadowTls(self.PASSWORD)
        captured = reference.switch_record(
            self.PASSWORD.encode(), self.SERVER_RANDOM, self.SESSION_ID, bytes(200)
        )
        _, step = self._switched(guard, captured, server_random=bytes([0xAA]) * 32)
        assert step.session_id is None
        assert step.forward == captured

    def test_a_switch_sealed_with_another_password_is_refused(self):
        guard = _rust.ShadowTls(self.PASSWORD)
        switch = reference.switch_record(b"otherpass", self.SERVER_RANDOM, self.SESSION_ID, bytes(200))
        _, step = self._switched(guard, switch)
        assert step.session_id is None

    def test_the_previous_password_is_still_accepted(self):
        guard = _rust.ShadowTls("new", "old")
        switch = reference.switch_record(b"old", self.SERVER_RANDOM, self.SESSION_ID, bytes(200))
        connection, step = self._switched(guard, switch)
        assert step.session_id == self.SESSION_ID

        server = connection.stream(True)
        client = reference.SealedStream.for_role(b"old", self.SERVER_RANDOM, self.SESSION_ID, server=False)
        assert client.unwrap(server.wrap(b"hello")) == b"hello"

    def test_the_padding_rust_adds_keeps_the_record_plausible(self):
        guard = _rust.ShadowTls(self.PASSWORD)
        sizes = {len(guard.seal_switch(self.SERVER_RANDOM, self.SESSION_ID)) for _ in range(32)}
        assert min(sizes) >= reference.RECORD_HEADER_LEN + reference.SWITCH_PREFIX_LEN + 128
        assert len(sizes) > 1


@requires_rust
@pytest.mark.crypto
class TestCrossRuntimeStream:
    PASSWORD = reference.PASSWORD.decode()

    def _pair(self, server_random=reference.SERVER_RANDOM, session_id=reference.SESSION_ID):
        guard = _rust.ShadowTls(self.PASSWORD)
        rust_server = guard.stream(server_random, session_id, True)
        python_client = reference.SealedStream.for_role(
            self.PASSWORD.encode(), server_random, session_id, server=False
        )
        return rust_server, python_client

    def test_python_opens_what_rust_sealed(self):
        rust_server, python_client = self._pair()
        assert python_client.unwrap(rust_server.wrap(b"hello")) == b"hello"

    def test_rust_opens_what_python_sealed(self):
        guard = _rust.ShadowTls(self.PASSWORD)
        rust_server = guard.stream(reference.SERVER_RANDOM, reference.SESSION_ID, True)
        python_client = reference.SealedStream.for_role(
            self.PASSWORD.encode(), reference.SERVER_RANDOM, reference.SESSION_ID, server=False
        )
        assert rust_server.unwrap(python_client.wrap(b"world")) == b"world"

    def test_the_counters_stay_in_step_across_runtimes(self):
        rust_server, python_client = self._pair()
        for index in range(4):
            assert python_client.unwrap(rust_server.wrap(bytes([index]) * 32)) == bytes([index]) * 32

    def test_a_repeated_session_id_on_a_new_connection_changes_the_keystream(self):
        first, _ = self._pair(server_random=bytes(32))
        second, _ = self._pair(server_random=bytes([1]) * 32)
        assert first.wrap(b"same") != second.wrap(b"same")

    def test_a_record_from_another_connection_does_not_open(self):
        first, _ = self._pair(server_random=bytes(32))
        _, client_of_second = self._pair(server_random=bytes([1]) * 32)
        assert client_of_second.unwrap(first.wrap(b"same")) is None
