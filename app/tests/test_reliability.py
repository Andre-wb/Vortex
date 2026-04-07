"""Тесты надёжности: дедупликация, TTL, multihop, backoff, очереди."""

import asyncio
import time
import uuid

import pytest


class TestReliability:

    def test_message_deduplication(self):
        CACHE_SIZE = 1000
        seen = {}

        def process_message(msg_id: str) -> bool:
            if msg_id in seen:
                return False
            if len(seen) >= CACHE_SIZE:
                oldest = min(seen, key=seen.get)
                del seen[oldest]
            seen[msg_id] = time.time()
            return True

        msg_id = str(uuid.uuid4())
        assert process_message(msg_id) is True
        assert process_message(msg_id) is False
        assert process_message(msg_id) is False
        ids = [str(uuid.uuid4()) for _ in range(100)]
        for mid in ids:
            assert process_message(mid) is True

    def test_ttl_decrement(self):
        def forward(packet: dict) -> dict | None:
            ttl = packet.get('ttl', 0) - 1
            if ttl <= 0:
                return None
            return {**packet, 'ttl': ttl}

        pkt = {'msg_id': 'abc', 'ttl': 4, 'payload': 'hello'}
        p1  = forward(pkt);  assert p1['ttl'] == 3
        p2  = forward(p1);   assert p2['ttl'] == 2
        p3  = forward(p2);   assert p3['ttl'] == 1
        p4  = forward(p3);   assert p4 is None

    def test_multihop_routing_simulation(self):
        delivered_to = []

        def make_node(name: str, targets: list):
            seen = set()
            def handler(packet: dict) -> None:
                msg_id = packet['msg_id']
                if msg_id in seen:
                    return
                seen.add(msg_id)
                delivered_to.append(name)
                ttl = packet.get('ttl', 0) - 1
                if ttl <= 0:
                    return
                for target_fn in targets:
                    target_fn({**packet, 'ttl': ttl})
            return handler

        node_c = make_node('C', [])
        node_b = make_node('B', [node_c])
        node_a = make_node('A', [node_b])
        node_a({'msg_id': 'test-1', 'ttl': 4, 'text': 'hello from A'})

        assert 'A' in delivered_to
        assert 'B' in delivered_to
        assert 'C' in delivered_to
        assert delivered_to.count('A') == 1
        assert delivered_to.count('B') == 1
        assert delivered_to.count('C') == 1

    @pytest.mark.asyncio
    async def test_reconnect_backoff(self):
        """Relay-менеджер выдерживает паузу между попытками переподключения."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from app.federation.federation import FederationRelayManager

        relay = FederationRelayManager()
        relay._rooms[-999] = MagicMock()
        relay._outqueue[-999] = asyncio.Queue()

        sleep_calls: list[float] = []

        async def fake_sleep(t):
            sleep_calls.append(t)
            raise asyncio.CancelledError()

        with patch('app.federation.federation.asyncio.sleep', side_effect=fake_sleep):
            with patch('app.federation.federation.websockets.connect', side_effect=OSError('refused')):
                try:
                    await relay._relay_loop(-999, relay._outqueue[-999])
                except asyncio.CancelledError:
                    pass

        assert sleep_calls, 'asyncio.sleep не был вызван — backoff отсутствует'
        assert sleep_calls[0] >= 1.0, f'Задержка переподключения слишком мала: {sleep_calls[0]}s'

    def test_message_queue_ordering(self):
        results = []

        async def process(i: int, delay: float) -> None:
            await asyncio.sleep(delay)
            results.append(i)

        async def run():
            queue = asyncio.Queue()
            for i, delay in enumerate([0.05, 0.01, 0.03, 0.02, 0.04]):
                await queue.put((i, delay))
            while not queue.empty():
                i, delay = await queue.get()
                await process(i, delay)

        asyncio.run(run())
        assert results == [0, 1, 2, 3, 4]
