import asyncio
import contextlib
import inspect
import socket

import pytest

from app.transport.stealth_level4 import RealityProtocol, ShadowTLS

SERVER_RANDOM = bytes(range(32))


def _record(ctype, payload):
    return bytes([ctype, 0x03, 0x03]) + len(payload).to_bytes(2, "big") + payload


def _server_hello(server_random=SERVER_RANDOM):
    body = b"\x03\x03" + server_random + b"\x20" + bytes(32) + b"\x13\x01" + b"\x00" + b"\x00\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return _record(0x16, handshake)


def _client_hello(host=b""):
    extensions = b""
    if host:
        entry = b"\x00" + len(host).to_bytes(2, "big") + host
        body = len(entry).to_bytes(2, "big") + entry
        extensions = b"\x00\x00" + len(body).to_bytes(2, "big") + body
    payload = (
        b"\x03\x03"
        + bytes(32)
        + b"\x20"
        + bytes(32)
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(payload).to_bytes(3, "big") + payload
    return _record(0x16, handshake)


class _Harness:
    def __init__(self, remote_handler, extra_donors=(), handshake_timeout=None):
        self._remote_handler = remote_handler
        self._extra_donors = list(extra_donors)
        self._handshake_timeout = handshake_timeout
        self.received_by_remote = bytearray()

    async def __aenter__(self):
        self._srv = await asyncio.start_server(self._on_remote, "127.0.0.1", 0)
        host, port = self._srv.sockets[0].getsockname()[:2]
        self.donor_port = port
        self.shadow = ShadowTLS(password="testpass", donors=[(host, port), *self._extra_donors])
        self.csock, ssock = socket.socketpair()
        self.csock.setblocking(False)
        self.client_reader, self.client_writer = await asyncio.open_connection(sock=ssock)
        self.loop = asyncio.get_running_loop()
        extra = {} if self._handshake_timeout is None else {"timeout": self._handshake_timeout}
        self.proxy_task = asyncio.create_task(
            self.shadow.server_handshake_proxy(self.client_reader, self.client_writer, **extra)
        )
        return self

    async def _on_remote(self, reader, writer):
        await self._remote_handler(self, reader, writer)

    async def send(self, data):
        await self.loop.sock_sendall(self.csock, data)

    async def recv_exactly(self, n, timeout=2.0):
        buf = b""
        while len(buf) < n:
            try:
                chunk = await asyncio.wait_for(self.loop.sock_recv(self.csock, n - len(buf)), timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def close_client_write(self):
        self.csock.shutdown(socket.SHUT_WR)

    async def finish(self):
        return await asyncio.wait_for(self.proxy_task, timeout=5.0)

    def switch_record(self, session_id, server_random=SERVER_RANDOM):
        return self.shadow.seal_switch(server_random, session_id)

    async def __aexit__(self, *exc):
        if not self.proxy_task.done():
            self.proxy_task.cancel()
            await asyncio.gather(self.proxy_task, return_exceptions=True)
        self.client_writer.close()
        self._srv.close()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._srv.wait_closed(), timeout=1.0)
        with contextlib.suppress(OSError):
            self.csock.close()


async def _sink(harness, reader, writer):
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            harness.received_by_remote.extend(data)
    except (ConnectionError, asyncio.CancelledError):
        pass


async def _greeting(harness, reader, writer):
    try:
        first = await reader.read(8192)
        harness.received_by_remote.extend(first)
        writer.write(_server_hello())
        await writer.drain()
        while True:
            data = await reader.read(8192)
            if not data:
                break
            harness.received_by_remote.extend(data)
    except (ConnectionError, asyncio.CancelledError):
        pass


async def test_switch_returns_session_id_and_the_data_that_followed():
    async with _Harness(_greeting) as h:
        await h.send(_client_hello())
        assert await h.recv_exactly(len(_server_hello())) == _server_hello()

        sid = bytes(range(16))
        switch = h.switch_record(sid)
        await h.send(switch)
        await h.send(b"DATA-AFTER-SWITCH")

        switched = await h.finish()
        assert switched.session_id == sid
        assert switched.trailing == b"DATA-AFTER-SWITCH"

        remote_got = bytes(h.received_by_remote)
        assert _client_hello() in remote_got
        assert switch not in remote_got
        assert b"DATA-AFTER-SWITCH" not in remote_got


async def test_the_stream_after_the_switch_talks_to_the_client():
    async with _Harness(_greeting) as h:
        await h.send(_client_hello())
        await h.recv_exactly(len(_server_hello()))

        sid = bytes([5]) * 16
        await h.send(h.switch_record(sid))
        switched = await h.finish()

        client = h.shadow.client_stream(SERVER_RANDOM, sid)
        assert client.unwrap(switched.stream.wrap(b"hello")) == b"hello"
        assert switched.stream.unwrap(client.wrap(b"world")) == b"world"


async def test_switch_record_split_across_tcp_segments():
    async with _Harness(_greeting) as h:
        await h.send(_client_hello())
        await h.recv_exactly(len(_server_hello()))

        sid = bytes([3]) * 16
        switch = h.switch_record(sid)
        await h.send(switch[:3])
        await asyncio.sleep(0.02)
        await h.send(switch[3:8])
        await asyncio.sleep(0.02)
        await h.send(switch[8:])

        switched = await h.finish()
        assert switched.session_id == sid
        assert switch not in bytes(h.received_by_remote)


async def test_a_switch_before_the_donor_answered_is_relayed_on():
    async with _Harness(_sink) as h:
        await h.send(_client_hello())
        switch = h.switch_record(bytes([7]) * 16)
        await h.send(switch)
        await asyncio.sleep(0.05)
        h.close_client_write()

        assert await h.finish() is None
        assert switch in bytes(h.received_by_remote)


async def test_a_switch_captured_from_another_connection_does_not_replay():
    async with _Harness(_greeting) as h:
        await h.send(_client_hello())
        await h.recv_exactly(len(_server_hello()))

        captured = h.switch_record(bytes([9]) * 16, server_random=bytes([0xAA]) * 32)
        await h.send(captured)
        await asyncio.sleep(0.05)
        h.close_client_write()

        assert await h.finish() is None
        assert captured in bytes(h.received_by_remote)


async def test_the_donor_is_the_name_the_client_asked_for():
    async def handler(harness, reader, writer):
        await _sink(harness, reader, writer)

    port_holder = {}

    async def on_second(reader, writer):
        port_holder["hit"] = True
        writer.close()

    second = await asyncio.start_server(on_second, "127.0.0.1", 0)
    second_port = second.sockets[0].getsockname()[1]
    try:
        async with _Harness(handler, extra_donors=[("localhost", second_port)]) as h:
            await h.send(_client_hello(b"localhost"))
            await asyncio.sleep(0.1)
            h.close_client_write()
            assert await h.finish() is None
            assert port_holder.get("hit") is True
            assert bytes(h.received_by_remote) == b""
    finally:
        second.close()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(second.wait_closed(), timeout=1.0)


async def test_a_name_outside_the_allowlist_lands_on_the_fallback_donor():
    async with _Harness(_sink) as h:
        await h.send(_client_hello(b"attacker.example"))
        await asyncio.sleep(0.05)
        h.close_client_write()
        assert await h.finish() is None
        assert _client_hello(b"attacker.example") in bytes(h.received_by_remote)


async def test_inflight_donor_record_reaches_client_whole():
    ticket = _record(0x17, b"NEWSESSIONTICKET-" + b"z" * 60)

    async def handler(harness, reader, writer):
        try:
            first = await reader.read(8192)
            harness.received_by_remote.extend(first)
            writer.write(_server_hello() + ticket)
            await writer.drain()
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                harness.received_by_remote.extend(data)
        except (ConnectionError, asyncio.CancelledError):
            pass

    async with _Harness(handler) as h:
        await h.send(_client_hello())

        got = await h.recv_exactly(len(_server_hello()) + len(ticket))
        assert got == _server_hello() + ticket, "запись донора обязана дойти целиком"

        sid = bytes([9]) * 16
        assert (await asyncio.gather(h.send(h.switch_record(sid)), h.finish()))[1].session_id == sid


async def test_real_client_steady_state_transparent_proxy():
    async def echo_records(harness, reader, writer):
        try:
            first = await reader.readexactly(5)
            length = int.from_bytes(first[3:5], "big")
            harness.received_by_remote.extend(first + await reader.readexactly(length))
            writer.write(_server_hello())
            await writer.drain()
            while True:
                header = await reader.readexactly(5)
                length = int.from_bytes(header[3:5], "big")
                payload = await reader.readexactly(length)
                harness.received_by_remote.extend(header + payload)
                writer.write(_record(0x17, b"resp-to-" + payload[:8]))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass

    async with _Harness(echo_records) as h:
        await h.send(_client_hello())
        assert await h.recv_exactly(len(_server_hello())) == _server_hello()

        await h.send(_record(0x17, b"request-one-data"))
        expected = _record(0x17, b"resp-to-" + b"request-")
        assert await h.recv_exactly(len(expected)) == expected

        h.close_client_write()
        assert await h.finish() is None
        assert _client_hello() in bytes(h.received_by_remote)
        assert _record(0x17, b"request-one-data") in bytes(h.received_by_remote)


async def test_non_tls_first_bytes_fall_back_to_transparent_proxy():
    async with _Harness(_sink) as h:
        await h.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await asyncio.sleep(0.05)
        h.close_client_write()
        assert await h.finish() is None
        assert b"GET / HTTP/1.1" in bytes(h.received_by_remote)


async def test_oversized_record_length_is_not_our_client():
    async with _Harness(_sink) as h:
        await h.send(bytes([0x17, 0x03, 0x03, 0xFF, 0xFF]))
        await h.send(b"\x00" * 64)
        await asyncio.sleep(0.05)
        h.close_client_write()
        assert await h.finish() is None
        assert bytes([0x17, 0x03, 0x03, 0xFF, 0xFF]) in bytes(h.received_by_remote)


def test_an_unconfigured_guard_refuses_to_seal():
    shadow = ShadowTLS(password="")
    if shadow.get_status()["configured"]:
        return
    with pytest.raises(ValueError):
        shadow.seal_switch(SERVER_RANDOM, bytes(16))


async def test_a_client_that_falls_silent_before_the_donor_does_not_hold_the_relay():
    async with _Harness(_sink, handshake_timeout=0.2) as h:
        await h.send(b"\x16\x03\x01")
        assert await h.finish() is None


async def test_a_client_that_falls_silent_after_the_donor_answered_does_not_hold_the_relay():
    async with _Harness(_greeting, handshake_timeout=0.3) as h:
        await h.send(_client_hello())
        assert await h.recv_exactly(len(_server_hello())) == _server_hello()
        assert await h.finish() is None


async def test_the_budget_covers_the_whole_handshake_and_not_each_read():
    """Клиент, капающий по байту, не продлевает рукопожатие бесконечно."""
    async with _Harness(_sink, handshake_timeout=0.3) as h:
        for _ in range(20):
            await h.send(b"\x16")
            await asyncio.sleep(0.03)
        assert await h.finish() is None


def test_the_relay_takes_its_budget_from_rust():
    from app.transport.timeout_backend import HANDSHAKE_TIMEOUT_SECS

    signature = inspect.signature(ShadowTLS.server_handshake_proxy)
    assert signature.parameters["timeout"].default == HANDSHAKE_TIMEOUT_SECS
    reality_signature = inspect.signature(RealityProtocol._read_client_hello)
    assert reality_signature.parameters["timeout"].default == HANDSHAKE_TIMEOUT_SECS
