"""Кросс-языковые golden-тесты Shadowsocks: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/shadowsocks_parity.json` (генератор
`scripts/gen_shadowsocks_parity_vectors.py`), вторая независимая реализация
формата — `app/tests/shadowsocks_parity_reference.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import shadowsocks_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "shadowsocks_parity.json"

FRAME_HOST = "www.example.com"
FRAME_PORT = 9000

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

    def test_a_refusal_is_frozen_as_carefully_as_an_answer(self):
        vectors = _vectors()
        refused = [v for v in vectors["seal_handshake"] if v["expected"]["stream"] is None]
        assert len(refused) >= 5
        outcomes = {v["expected"]["outcome"] for v in vectors["open_handshake"]}
        assert outcomes == {"accepted", "unauthorized", "need_more", "malformed"}


@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


def _guard(passwords: list[str]):
    guard = _rust.Shadowsocks(passwords[0] if passwords else "")
    for extra in passwords[1:]:
        guard.add_password(extra)
    return guard


def _session(password: str, salt: bytes, role: str):
    """Сеанс нужной роли, доведённый до того же места, что и эталон."""
    guard = _rust.Shadowsocks(password)
    client = guard.connect_with(FRAME_HOST, FRAME_PORT, b"", salt, b"")
    if role == reference.CLIENT:
        return client
    _, server = guard.accept(client.stream)
    return server


def _rust_seal_handshake(args: dict) -> dict:
    guard = _rust.Shadowsocks(args["password"])
    try:
        session = guard.connect_with(
            args["host"],
            args["port"],
            bytes.fromhex(args["data"]),
            bytes.fromhex(args["salt"]),
            bytes.fromhex(args["padding"]),
        )
    except ValueError:
        return {"stream": None}
    return {"stream": session.stream.hex()}


def _rust_open_handshake(args: dict) -> dict:
    status, session = _guard(args["passwords"]).accept(bytes.fromhex(args["stream"]))
    if session is None:
        return {"outcome": status, "host": None, "port": None, "payload": None, "consumed": 0}
    return {
        "outcome": status,
        "host": session.host,
        "port": session.port,
        "payload": session.payload.hex(),
        "consumed": session.consumed,
    }


def _rust_seal_frames(args: dict) -> dict:
    session = _session(args["password"], bytes.fromhex(args["salt"]), args["role"])
    frames = session.seal(bytes.fromhex(args["data"]))
    return {"frames": frames.hex(), "counter": session.sealed_frames * 2}


def _rust_open_frames(args: dict) -> dict:
    session = _session(args["password"], bytes.fromhex(args["salt"]), args["role"])
    drained = session.drain(bytes.fromhex(args["buffer"]))
    if drained is None:
        return {"outcome": "malformed", "data": None, "consumed": 0, "counter": 0}
    consumed, data = drained
    return {
        "outcome": "opened",
        "data": data.hex(),
        "consumed": consumed,
        "counter": session.opened_frames * 2,
    }


RUST_IMPLEMENTATIONS = {
    "seal_handshake": _rust_seal_handshake,
    "open_handshake": _rust_open_handshake,
    "seal_frames": _rust_seal_frames,
    "open_frames": _rust_open_frames,
}

RUST_CASES = [case for case in ALL_CASES if case.values[0].name in RUST_IMPLEMENTATIONS]


@requires_rust
@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", RUST_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


@pytest.mark.crypto
class TestKeySchedule:
    PASSWORD = reference.PASSWORD.decode()

    def test_the_key_schedule_is_checked_through_the_bytes_it_produces(self):
        """Ключи наружу не выставлены и не должны быть: их сверяет сам шифртекст.

        `seal_handshake` — чистая функция от (пароль, соль, паддинг, адрес,
        данные); совпасть байт-в-байт она может только если совпали и ключ
        пароля, и ключ направления.
        """
        assert set(_vectors()) - set(RUST_IMPLEMENTATIONS) == {"password_key", "direction_keys"}
        sealed = {v["args"]["salt"] for v in _vectors()["seal_handshake"] if v["expected"]["stream"]}
        assert {v["args"]["salt"] for v in _vectors()["direction_keys"]} <= sealed

    def test_the_two_roles_name_the_same_pair_of_keys(self):
        by_role = {}
        for vector in _vectors()["direction_keys"]:
            args = vector["args"]
            if args["password"] == self.PASSWORD and args["salt"] == "11" * reference.SALT_LEN:
                by_role[args["role"]] = vector["expected"]
        assert set(by_role) == {reference.CLIENT, reference.SERVER}
        assert by_role[reference.CLIENT]["send"] == by_role[reference.SERVER]["recv"]
        assert by_role[reference.SERVER]["send"] == by_role[reference.CLIENT]["recv"]
        assert by_role[reference.CLIENT]["send"] != by_role[reference.CLIENT]["recv"]

    def test_no_two_passwords_or_salts_share_a_key(self):
        keys = [v["expected"]["send"] for v in _vectors()["direction_keys"]]
        keys += [v["expected"]["recv"] for v in _vectors()["direction_keys"]]
        assert len(set(keys)) == 2 * len(_vectors()["direction_keys"]) - 2

    def test_an_empty_password_has_no_key(self):
        empty = [v for v in _vectors()["password_key"] if v["args"]["password"] == ""]
        assert [v["expected"]["key"] for v in empty] == [None]


@pytest.mark.crypto
class TestWireFormat:
    def test_the_prologue_is_thirty_two_bytes_and_the_frame_costs_thirty_four(self):
        stream = bytes.fromhex(_vectors()["seal_handshake"][0]["expected"]["stream"])
        body = reference.encode_request_body("www.example.com", 9000, b"", b"hello ss")
        assert len(stream) == reference.SALT_LEN + reference.LENGTH_CHUNK_LEN + len(body) + reference.TAG_LEN

    def test_the_destination_and_the_payload_never_travel_in_the_clear(self):
        checked = 0
        for vector in _vectors()["seal_handshake"]:
            if not vector["expected"]["stream"]:
                continue
            stream = bytes.fromhex(vector["expected"]["stream"])
            assert vector["args"]["host"].encode() not in stream
            payload = bytes.fromhex(vector["args"]["data"])
            if payload:
                assert payload not in stream
                checked += 1
        assert checked >= 3, "ни одного вектора с полезной нагрузкой"

    def test_the_same_request_under_two_salts_shares_nothing_after_the_prologue(self):
        vectors = _vectors()["seal_handshake"]
        one = bytes.fromhex(vectors[0]["expected"]["stream"])
        other = bytes.fromhex(vectors[2]["expected"]["stream"])
        assert vectors[0]["args"]["salt"] != vectors[2]["args"]["salt"]
        assert one[reference.SALT_LEN :] != other[reference.SALT_LEN :]

    def test_the_length_on_the_wire_is_not_the_length_of_the_rest(self):
        stream = bytes.fromhex(_vectors()["seal_handshake"][0]["expected"]["stream"])
        declared = int.from_bytes(stream[reference.SALT_LEN : reference.SALT_LEN + 2], "big")
        assert declared != len(stream) - reference.SALT_LEN - reference.LENGTH_CHUNK_LEN


@requires_rust
@pytest.mark.crypto
class TestCrossRuntime:
    PASSWORD = reference.PASSWORD.decode()

    @pytest.mark.parametrize(
        "host,port",
        [
            ("www.example.com", 9000),
            ("13.10.1.2", 443),
            ("13.10.13.10", 3338),
            ("2001:db8::1", 443),
            ("a.example", 1),
        ],
    )
    def test_rust_accepts_what_python_sealed(self, host, port):
        stream = reference.seal_handshake(reference.PASSWORD, bytes(32), b"", host, port, b"payload")
        status, session = _rust.Shadowsocks(self.PASSWORD).accept(stream)
        assert status == "accepted"
        assert session.host == host
        assert session.port == port
        assert session.payload == b"payload"

    @pytest.mark.parametrize(
        "host,port",
        [
            ("www.example.com", 9000),
            ("13.10.1.2", 443),
            ("13.10.13.10", 3338),
            ("2001:db8::1", 443),
        ],
    )
    def test_python_opens_what_rust_sealed(self, host, port):
        session = _rust.Shadowsocks(self.PASSWORD).connect_with(host, port, b"payload", bytes(32), b"")
        opened = reference.open_handshake([reference.PASSWORD], session.stream)
        assert opened["outcome"] == "accepted"
        assert opened["host"] == host
        assert opened["port"] == port
        assert bytes.fromhex(opened["payload"]) == b"payload"

    def test_the_two_runtimes_keep_talking_after_the_request(self):
        guard = _rust.Shadowsocks(self.PASSWORD)
        stream = reference.seal_handshake(reference.PASSWORD, bytes(32), b"", "example.com", 80, b"")
        status, server = guard.accept(stream)
        assert status == "accepted"

        key = reference.password_key(reference.PASSWORD)
        client_send, client_recv = reference.direction_keys(key, bytes(32), reference.CLIENT)

        there, _ = reference.seal_stream(client_send, 2, b"ping")
        assert server.open(there) == b"ping"

        back = server.seal(b"pong")
        outcome, data, consumed, _ = reference.drain(client_recv, 0, back)
        assert outcome == "opened"
        assert data == b"pong"
        assert consumed == len(back)

    def test_a_padded_request_from_python_is_read_the_same_by_rust(self):
        stream = reference.seal_handshake(
            reference.PASSWORD, bytes(32), bytes(reference.MAX_PADDING), "example.com", 80, b"tail"
        )
        status, session = _rust.Shadowsocks(self.PASSWORD).accept(stream)
        assert status == "accepted"
        assert session.payload == b"tail"

    def test_the_previous_password_is_still_accepted(self):
        guard = _rust.Shadowsocks("newer_password", self.PASSWORD)
        stream = reference.seal_handshake(reference.PASSWORD, bytes(32), b"", "example.com", 80, b"")
        assert guard.accept(stream)[0] == "accepted"

    def test_an_added_password_survives_a_rotation(self):
        guard = _rust.Shadowsocks("newer_password")
        guard.add_password(self.PASSWORD)
        guard.reload("newest_password", "newer_password")
        stream = reference.seal_handshake(reference.PASSWORD, bytes(32), b"", "example.com", 80, b"")
        assert guard.accept(stream)[0] == "accepted"

    def test_an_unknown_password_is_refused_the_same_way_as_noise(self):
        guard = _rust.Shadowsocks(self.PASSWORD)
        stranger = reference.seal_handshake(reference.STRANGER_PASSWORD, bytes(32), b"", "example.com", 80, b"")
        noise = bytes(range(256)) * 2
        assert guard.accept(stranger)[0] == "unauthorized"
        assert guard.accept(noise)[0] == "unauthorized"


@requires_rust
@pytest.mark.crypto
class TestStreamingBoundary:
    PASSWORD = reference.PASSWORD.decode()

    def test_a_request_arriving_byte_by_byte_asks_for_more_until_it_is_whole(self):
        guard = _rust.Shadowsocks(self.PASSWORD)
        stream = reference.seal_handshake(reference.PASSWORD, bytes(32), b"", "example.com", 80, b"payload")
        for cut in range(len(stream)):
            assert guard.accept(stream[:cut])[0] == "need_more", cut
            assert reference.open_handshake([reference.PASSWORD], stream[:cut])["outcome"] == "need_more", cut
        assert guard.accept(stream)[0] == "accepted"

    def test_nothing_incomplete_is_ever_longer_than_the_biggest_frame(self):
        guard = _rust.Shadowsocks(self.PASSWORD)
        payload = b"A" * (reference.MAX_PAYLOAD * 2)
        stream = reference.seal_handshake(reference.PASSWORD, bytes(32), b"", "example.com", 80, payload)
        for cut in range(0, len(stream), 97):
            if guard.accept(stream[:cut])[0] == "need_more":
                assert cut < reference.SALT_LEN + reference.MAX_FRAME, cut

    def test_a_read_that_ends_mid_frame_loses_neither_the_frames_before_it_nor_the_session(self):
        guard = _rust.Shadowsocks(self.PASSWORD)
        client = guard.connect_with("example.com", 80, b"", bytes(32), b"")
        _, server = guard.accept(client.stream)
        stream = client.seal(b"one") + client.seal(b"two")

        consumed, data = server.drain(stream[:-1])
        assert data == b"one"
        assert consumed < len(stream)
        rest, tail = server.drain(stream[consumed:])
        assert tail == b"two"
        assert consumed + rest == len(stream)

    def test_an_empty_message_produces_no_frame_at_all(self):
        guard = _rust.Shadowsocks(self.PASSWORD)
        client = guard.connect_with("example.com", 80, b"", bytes(32), b"")
        assert client.seal(b"") == b""
        with pytest.raises(ValueError):
            client.seal_one(b"")
