import asyncio
import contextlib
import socket

from app.transport.stealth_level4 import ShadowTLS


def _record(ctype, payload):
    return bytes([ctype, 0x03, 0x03]) + len(payload).to_bytes(2, "big") + payload


class _Harness:
    def __init__(self, remote_handler):
        self._remote_handler = remote_handler
        self.received_by_remote = bytearray()

    async def __aenter__(self):
        self._srv = await asyncio.start_server(self._on_remote, "127.0.0.1", 0)
        host, port = self._srv.sockets[0].getsockname()[:2]
        self.shadow = ShadowTLS(password="testpass")
        self.shadow.get_handshake_target = lambda: (host, port)
        self.csock, ssock = socket.socketpair()
        self.csock.setblocking(False)
        self.client_reader, self.client_writer = await asyncio.open_connection(sock=ssock)
        self.loop = asyncio.get_running_loop()
        self.proxy_task = asyncio.create_task(
            self.shadow.server_handshake_proxy(self.client_reader, self.client_writer)
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

    async def read_client_tail(self, timeout=1.0):
        try:
            return await asyncio.wait_for(self.client_reader.read(4096), timeout)
        except asyncio.TimeoutError:
            return b""

    async def __aexit__(self, *exc):
        if not self.proxy_task.done():
            self.proxy_task.cancel()
            await asyncio.gather(self.proxy_task, return_exceptions=True)
        self.client_writer.close()
        self._srv.close()
        await self._srv.wait_closed()
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


async def test_switch_returns_session_id_and_preserves_stream():
    async with _Harness(_sink) as h:
        client_hello = _record(0x16, b"CLIENTHELLO-cover")
        finished = _record(0x17, b"x" * 53)
        await h.send(client_hello)
        await h.send(finished)
        await asyncio.sleep(0.05)

        sid = bytes(range(16))
        switch = _record(0x17, sid + h.shadow.generate_switch_marker(sid))
        await h.send(switch)
        await h.send(b"DATA-AFTER-SWITCH")

        session_id = await h.finish()
        assert session_id == sid

        remote_got = bytes(h.received_by_remote)
        assert client_hello in remote_got
        assert finished in remote_got
        assert switch not in remote_got
        assert b"DATA-AFTER-SWITCH" not in remote_got

        tail = await h.read_client_tail()
        assert tail == b"DATA-AFTER-SWITCH"


async def test_switch_record_split_across_tcp_segments():
    async with _Harness(_sink) as h:
        await h.send(_record(0x16, b"CH"))
        await asyncio.sleep(0.02)

        sid = bytes([3]) * 16
        switch = _record(0x17, sid + h.shadow.generate_switch_marker(sid))
        await h.send(switch[:3])
        await asyncio.sleep(0.02)
        await h.send(switch[3:8])
        await asyncio.sleep(0.02)
        await h.send(switch[8:])

        assert await h.finish() == sid
        assert switch not in bytes(h.received_by_remote)


async def test_switch_record_may_be_padded():
    async with _Harness(_sink) as h:
        sid = bytes([7]) * 16
        payload = sid + h.shadow.generate_switch_marker(sid) + b"\x00" * 120
        await h.send(_record(0x16, b"CH"))
        await asyncio.sleep(0.02)
        await h.send(_record(0x17, payload))
        assert await h.finish() == sid
        assert b"\x00" * 120 not in bytes(h.received_by_remote)


async def test_inflight_server_record_reaches_client_whole():
    ticket = _record(0x17, b"NEWSESSIONTICKET-" + b"z" * 60)

    async def handler(harness, reader, writer):
        try:
            first = await reader.read(8192)
            harness.received_by_remote.extend(first)
            writer.write(ticket)
            await writer.drain()
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                harness.received_by_remote.extend(data)
        except (ConnectionError, asyncio.CancelledError):
            pass

    async with _Harness(handler) as h:
        await h.send(_record(0x16, b"CLIENTHELLO"))

        got = await h.recv_exactly(len(ticket))
        assert got == ticket, "server record must arrive whole, not truncated"

        sid = bytes([9]) * 16
        switch = _record(0x17, sid + h.shadow.generate_switch_marker(sid))
        await h.send(switch)
        assert await h.finish() == sid


async def test_real_client_steady_state_transparent_proxy():
    async def echo_records(harness, reader, writer):
        try:
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
        await h.send(_record(0x16, b"CLIENTHELLO"))
        r1 = await h.recv_exactly(len(_record(0x17, b"resp-to-" + b"CLIENTHE")))
        assert r1 == _record(0x17, b"resp-to-" + b"CLIENTHE")

        await h.send(_record(0x17, b"request-one-data"))
        r2 = await h.recv_exactly(len(_record(0x17, b"resp-to-" + b"request-")))
        assert r2 == _record(0x17, b"resp-to-" + b"request-")

        h.close_client_write()
        assert await h.finish() is None
        assert _record(0x16, b"CLIENTHELLO") in bytes(h.received_by_remote)
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


def test_match_switch_record_rejects_forgeries():
    shadow = ShadowTLS(password="testpass")
    sid = bytes(range(16))
    good = sid + shadow.generate_switch_marker(sid)
    assert shadow._match_switch_record(0x17, good) == sid
    assert shadow._match_switch_record(0x16, good) is None
    assert shadow._match_switch_record(0x17, sid + b"\x00" * 8) is None
    assert shadow._match_switch_record(0x17, good[:20]) is None
    assert shadow._match_switch_record(0x17, good + b"pad") == sid
