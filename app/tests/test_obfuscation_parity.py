"""Кросс-языковые golden-тесты обфускации: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/obfuscation_parity.json` (генератор
`scripts/gen_obfuscation_parity_vectors.py`), вторая независимая реализация
форматов — `app/tests/obfuscation_parity_reference.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import obfuscation_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "obfuscation_parity.json"

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

    def test_refusals_are_part_of_the_contract(self):
        vectors = _vectors()
        refusals = sum(
            1
            for name in vectors
            for vector in vectors[name]
            if None in vector["expected"].values()
            or any(step["status"] != reference.OPENED for step in (vector["expected"].get("steps") or []))
        )
        assert refusals >= 18, "отказы обязаны быть заморожены наравне с успехами"


@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


def _session(args: dict):
    frames = _rust.ObfuscationFrames(bytes.fromhex(args["secret"]))
    salt = bytes.fromhex(args["salt"])
    if args["role"] == reference.INITIATOR:
        return frames.begin_with_salt(salt)
    return frames.accept(salt)


def _rust_pad(args: dict) -> dict:
    try:
        envelope = _rust.Obfuscation().pad_with(bytes.fromhex(args["data"]), bytes.fromhex(args["padding"]))
    except ValueError:
        return {"envelope": None}
    return {"envelope": envelope.hex()}


def _rust_unpad(args: dict) -> dict:
    try:
        data = _rust.Obfuscation().unpad(bytes.fromhex(args["envelope"]))
    except ValueError:
        return {"data": None}
    return {"data": data.hex()}


def _rust_seal_frames(args: dict) -> dict:
    try:
        session = _session(args)
    except ValueError:
        return {"frames": None}
    frames = []
    for frame in args["frames"]:
        try:
            sealed = session.wrap_one(bytes.fromhex(frame["data"]), bytes.fromhex(frame["padding"]))
        except ValueError:
            return {"frames": None}
        frames.append(sealed.hex())
    return {"frames": frames}


def _rust_open_frames(args: dict) -> dict:
    try:
        session = _session(args)
    except ValueError:
        return {"steps": None}
    steps = []
    for buffer in args["buffers"]:
        step = session.step(bytes.fromhex(buffer))
        steps.append(
            {
                "status": step.status,
                "consumed": step.consumed,
                "data": None if step.data is None else step.data.hex(),
            }
        )
    return {"steps": steps}


RUST_IMPLEMENTATIONS = {
    "pad": _rust_pad,
    "unpad": _rust_unpad,
    "seal_frames": _rust_seal_frames,
    "open_frames": _rust_open_frames,
}


@requires_rust
@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


@pytest.mark.crypto
class TestEnvelopeFormat:
    def test_the_header_is_two_lengths_and_the_message_follows_it(self):
        envelope = reference.pad(b"abc", bytes(16))
        assert envelope[: reference.HEADER_LEN] == b"\x00\x03\x00\x10"
        assert envelope[reference.HEADER_LEN : reference.HEADER_LEN + 3] == b"abc"

    def test_a_message_that_was_never_padded_is_not_silently_returned(self):
        never_padded = b"A" * 70000
        assert reference.unpad(never_padded) is None

    @requires_rust
    def test_a_message_too_long_for_the_format_is_refused_in_both_runtimes(self):
        too_long = b"A" * (reference.MAX_FIELD + 1)
        assert reference.pad(too_long, bytes(16)) is None
        with pytest.raises(ValueError):
            _rust.Obfuscation().pad_with(too_long, bytes(16))

    @requires_rust
    def test_a_buffer_that_was_never_padded_is_refused_in_both_runtimes(self):
        never_padded = b"A" * 70000
        assert reference.unpad(never_padded) is None
        with pytest.raises(ValueError):
            _rust.Obfuscation().unpad(never_padded)


@pytest.mark.crypto
@requires_rust
class TestCrossRuntimeFrames:
    SECRET = b"cross-runtime-secret"
    SALT = bytes(range(16))

    def _reference_keys(self, role: str) -> dict:
        return reference.session_keys(self.SECRET, self.SALT, role)

    def test_python_seals_and_rust_opens(self):
        keys = self._reference_keys(reference.INITIATOR)
        frame = reference.seal_frame(keys, 0, b"from python", bytes(64))
        session = _rust.ObfuscationFrames(self.SECRET).accept(self.SALT)
        assert session.unwrap(frame) == b"from python"

    def test_rust_seals_and_python_opens(self):
        session = _rust.ObfuscationFrames(self.SECRET).begin_with_salt(self.SALT)
        frame = session.wrap_one(b"from rust", bytes(64))
        keys = self._reference_keys(reference.RESPONDER)
        assert reference.open_frame(keys, 0, frame)["data"] == b"from rust"

    def test_a_whole_stream_survives_the_round_trip(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        initiator = frames.begin()
        responder = frames.accept(initiator.prologue)
        payload = b"x" * 40000
        assert responder.unwrap(initiator.wrap(payload)) == payload

    def test_a_frame_captured_from_the_wire_never_opens_twice(self):
        """Маска длины зависит от счётчика, поэтому повтор виден то как malformed,
        то как need_more — важно лишь то, что открытым он не будет никогда."""
        frames = _rust.ObfuscationFrames(self.SECRET)
        initiator = frames.begin()
        responder = frames.accept(initiator.prologue)
        frame = initiator.wrap(b"replay me")
        assert responder.unwrap(frame) == b"replay me"
        assert responder.step(frame).status != reference.OPENED
        assert responder.unwrap(frame) is None

    def test_a_read_that_ends_mid_frame_loses_nothing(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        initiator = frames.begin()
        responder = frames.accept(initiator.prologue)
        stream = initiator.wrap(b"one") + initiator.wrap(b"two")
        assert responder.unwrap(stream[:-1]) is None
        assert responder.opened_frames == 0
        assert responder.unwrap(stream) == b"onetwo"

    def test_a_partial_read_is_drained_up_to_the_last_whole_frame(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        initiator = frames.begin()
        responder = frames.accept(initiator.prologue)
        first = initiator.wrap(b"one")
        stream = first + initiator.wrap(b"two")
        consumed, data = responder.drain(stream[:-1])
        assert (consumed, data) == (len(first), b"one")
        assert responder.drain(stream[consumed:]) == (len(stream) - consumed, b"two")

    def test_a_frame_from_another_session_does_not_open(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        first = frames.begin()
        frame = first.wrap(b"body")
        second = frames.begin()
        listener = frames.accept(second.prologue)
        assert listener.unwrap(frame) is None

    def test_the_message_never_appears_on_the_wire(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        session = frames.begin()
        marker = b"plaintext-marker"
        assert marker not in session.wrap(marker)

    def test_a_frame_arriving_byte_by_byte_asks_for_more_until_it_is_whole(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        initiator = frames.begin()
        responder = frames.accept(initiator.prologue)
        frame = initiator.wrap(b"partial")
        for taken in range(len(frame)):
            assert responder.step(frame[:taken]).status == reference.NEED_MORE
        assert responder.step(frame).status == reference.OPENED

    def test_an_empty_secret_seals_nothing_and_accepts_nothing(self):
        frames = _rust.ObfuscationFrames(b"")
        assert frames.is_configured is False
        with pytest.raises(ValueError):
            frames.begin()
        with pytest.raises(ValueError):
            frames.accept(self.SALT)

    def test_a_stranger_with_another_secret_opens_nothing(self):
        frames = _rust.ObfuscationFrames(self.SECRET)
        initiator = frames.begin()
        frame = initiator.wrap(b"body")
        stranger = _rust.ObfuscationFrames(b"another-secret").accept(initiator.prologue)
        assert stranger.unwrap(frame) is None
