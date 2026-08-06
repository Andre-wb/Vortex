"""Кросс-языковые golden-тесты REALITY: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/reality_parity.json` (генератор
`scripts/gen_reality_parity_vectors.py`), эталоны —
`app/tests/reality_parity_reference.py`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from app.tests import reality_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "reality_parity.json"

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


def _rust_public_key(args: dict) -> dict:
    auth = _rust.RealityAuth(bytes.fromhex(args["secret"]))
    return {"public_key": auth.public_key().hex()}


def _rust_seal(args: dict) -> dict:
    auth = _rust.RealityAuth()
    ephemeral_pub, session_id = auth.build_client_hello_auth_derand(
        args["short_id"],
        bytes.fromhex(args["server_public"]),
        args["timestamp"],
        bytes.fromhex(args["ephemeral_secret"]),
    )
    return {"ephemeral_public": ephemeral_pub.hex(), "session_id": session_id.hex()}


def _rust_parse(args: dict) -> dict:
    parsed = _rust.RealityAuth.parse_client_hello(bytes.fromhex(args["client_hello"]))
    if parsed is None:
        return {"parsed": False, "session_id": None, "key_share": None}
    session_id, key_share = parsed
    return {
        "parsed": True,
        "session_id": session_id.hex(),
        "key_share": key_share.hex() if key_share is not None else None,
    }


RUST_IMPLEMENTATIONS = {
    "public_key": _rust_public_key,
    "seal": _rust_seal,
    "parse_client_hello": _rust_parse,
}


@requires_rust
@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


@requires_rust
@pytest.mark.crypto
class TestCrossRuntimeHandshake:
    SECRET = bytes.fromhex(reference.SERVER_SECRET)
    SHORT_ID = "deadbeef"

    def _server(self):
        auth = _rust.RealityAuth(self.SECRET)
        auth.add_short_id(self.SHORT_ID)
        return auth

    def test_rust_accepts_an_envelope_sealed_by_python(self):
        server = self._server()
        ephemeral_pub, session_id = reference.seal(
            "77" * 32, server.public_key().hex(), int(time.time()), self.SHORT_ID
        )
        assert server.verify_client_hello_auth(ephemeral_pub, session_id) == (True, self.SHORT_ID)

    def test_python_opens_an_envelope_sealed_by_rust(self):
        server = self._server()
        client = _rust.RealityAuth()
        timestamp = int(time.time())
        ephemeral_pub, session_id = client.build_client_hello_auth(
            self.SHORT_ID, server.public_key(), timestamp
        )
        opened = reference.open_envelope(reference.SERVER_SECRET, ephemeral_pub, session_id)
        assert opened == (reference.ENVELOPE_VERSION, timestamp, self.SHORT_ID)

    def test_a_replayed_envelope_is_refused(self):
        server = self._server()
        ephemeral_pub, session_id = reference.seal(
            "78" * 32, server.public_key().hex(), int(time.time()), self.SHORT_ID
        )
        assert server.verify_client_hello_auth(ephemeral_pub, session_id)[0] is True
        assert server.verify_client_hello_auth(ephemeral_pub, session_id) == (False, "")

    def test_a_stale_envelope_is_refused(self):
        server = self._server()
        ephemeral_pub, session_id = reference.seal(
            "79" * 32, server.public_key().hex(), int(time.time()) - 121, self.SHORT_ID
        )
        assert server.verify_client_hello_auth(ephemeral_pub, session_id) == (False, "")

    def test_an_unknown_short_id_is_refused(self):
        server = self._server()
        ephemeral_pub, session_id = reference.seal(
            "7a" * 32, server.public_key().hex(), int(time.time()), "cafebabe"
        )
        assert server.verify_client_hello_auth(ephemeral_pub, session_id) == (False, "")

    def test_a_stranger_key_is_refused(self):
        server = self._server()
        stranger_public = reference.public_key_of("66" * 32)
        ephemeral_pub, session_id = reference.seal(
            "7b" * 32, stranger_public.hex(), int(time.time()), self.SHORT_ID
        )
        assert server.verify_client_hello_auth(ephemeral_pub, session_id) == (False, "")

    def test_a_full_client_hello_authenticates_end_to_end(self):
        server = self._server()
        ephemeral_pub, session_id = reference.seal(
            "7c" * 32, server.public_key().hex(), int(time.time()), self.SHORT_ID
        )
        hello = reference.wrap_tls_record(
            reference.build_client_hello(session_id, reference.build_key_share_extension(ephemeral_pub))
        )
        assert server.is_reality_client(hello) == (True, self.SHORT_ID)

    def test_a_probe_without_our_envelope_is_refused(self):
        server = self._server()
        hello = reference.wrap_tls_record(
            reference.build_client_hello(b"\xab" * 32, reference.build_key_share_extension(b"\xcd" * 32))
        )
        assert server.is_reality_client(hello) == (False, "")
