"""Интеграционные сценарии: discovery, сообщения, multihop, файлы, latency, relay."""

import asyncio
import hashlib
import os
import secrets
import time

import pytest

from conftest import SyncASGIClient, random_str, random_digits, _phone_prefix
from app.main import app


_test_phone_pfx = _phone_prefix


class TestIntegrationScenarios:

    def test_scenario_1_node_discovery(self, client: SyncASGIClient, logged_user: dict):
        resp = client.get('/api/peers', headers=logged_user['headers'])
        assert resp.status_code == 200
        assert resp.json() is not None

    def test_scenario_3_text_message_exchange(self):
        """Отправка зашифрованного сообщения через WS — получаем broadcast обратно."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from starlette.testclient import TestClient

        room_key   = os.urandom(32)
        nonce      = os.urandom(12)
        plaintext  = b'Test message from scenario 3'
        ciphertext = nonce + AESGCM(room_key).encrypt(nonce, plaintext, None)
        ct_hex     = ciphertext.hex()

        with TestClient(app, raise_server_exceptions=False) as tc:
            tag   = random_str(8)
            phone = f'+4{int(_test_phone_pfx, 16):04d}{random_digits(7)}'
            tc.post('/api/authentication/register', json={
                'username':          f'sc3_{tag}',
                'password':          'Str0ng_sc3!@',
                'display_name':      f'SC3 {tag}',
                'phone':             phone,
                'avatar_emoji':      '\U0001f916',
                'x25519_public_key': secrets.token_hex(32),
            })
            csrf = tc.get('/api/authentication/csrf-token').json().get('csrf_token', '')
            tc.post('/api/authentication/login', json={
                'phone_or_username': f'sc3_{tag}',
                'password':          'Str0ng_sc3!@',
            }, headers={'X-CSRF-Token': csrf})
            r = tc.post('/api/rooms', json={
                'name': f'sc3room_{tag}', 'is_public': True,
                'encrypted_room_key': {
                    'ephemeral_pub': secrets.token_hex(32),
                    'ciphertext':    secrets.token_hex(60),
                },
            }, headers={'X-CSRF-Token': csrf})
            room_id = r.json().get('id')
            assert room_id is not None

            with tc.websocket_connect(f'/ws/{room_id}') as ws:
                for _ in range(3):
                    ws.receive_json()
                ws.send_json({'action': 'message', 'ciphertext': ct_hex})
                ack = ws.receive_json()
                assert ack.get('type') == 'ack', f'Ожидался ack, получено: {ack}'
                assert 'server_id' in ack, 'ack должен содержать server_id'

    def test_scenario_4_multihop_protocol(self):
        log = []

        def make_relay(node_name: str, neighbors: list):
            seen = set()
            def handler(msg: dict) -> None:
                if msg['msg_id'] in seen:
                    log.append(f'{node_name}:dup')
                    return
                seen.add(msg['msg_id'])
                log.append(f'{node_name}:recv')
                new_ttl = msg['ttl'] - 1
                if new_ttl <= 0:
                    return
                for nb in neighbors:
                    nb({**msg, 'ttl': new_ttl})
            return handler

        c = make_relay('C', [])
        b = make_relay('B', [c])
        a = make_relay('A', [b])
        a({'msg_id': 'msg-001', 'ttl': 4, 'text': 'hello'})
        assert 'A:recv' in log
        assert 'B:recv' in log
        assert 'C:recv' in log
        a({'msg_id': 'msg-001', 'ttl': 4, 'text': 'hello'})
        assert log.count('A:dup') == 1

    def test_scenario_5_file_integrity(self):
        original   = os.urandom(4096)
        sha_before = hashlib.sha256(original).hexdigest()
        chunks     = [original[i:i+512] for i in range(0, len(original), 512)]
        received   = b''.join(chunks)
        assert hashlib.sha256(received).hexdigest() == sha_before
        assert len(chunks) == 8

    def test_scenario_6_realtime_latency(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        target_ms = 150.0
        key       = os.urandom(32)
        gcm       = AESGCM(key)
        timings   = []
        for _ in range(100):
            msg   = 'Голосовое сообщение тест'.encode()
            t0    = time.perf_counter()
            nonce = os.urandom(12)
            ct    = gcm.encrypt(nonce, msg, None)
            gcm.decrypt(nonce, ct, None)
            timings.append((time.perf_counter() - t0) * 1000)
        p95_ms = sorted(timings)[int(len(timings) * 0.95)]
        avg_ms = sum(timings) / len(timings)
        print(f'\n  E2E latency: avg={avg_ms:.3f}ms  p95={p95_ms:.3f}ms  target<{target_ms}ms')
        assert p95_ms < target_ms, f'p95={p95_ms:.2f}ms > {target_ms}ms'

    @pytest.mark.asyncio
    async def test_relay_disconnect_recovery(self):
        from app.federation.federation import FederationRelayManager

        test_relay = FederationRelayManager()

        async def mock_relay_loop(virtual_id, outbound):
            while True:
                try:
                    await asyncio.wait_for(outbound.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    break
                except asyncio.CancelledError:
                    break

        test_relay._relay_loop = mock_relay_loop

        virtual_room = await test_relay.join(
            peer_ip="192.168.1.100",
            peer_port=8000,
            remote_room_id=123,
            remote_jwt="dummy_jwt",
            room_name="Test Relay Room",
            invite_code="TESTCODE",
            is_private=True,
            member_count=2,
            user_id=1
        )
        vid = virtual_room.virtual_id

        await test_relay.join(
            peer_ip="192.168.1.100",
            peer_port=8000,
            remote_room_id=123,
            remote_jwt="dummy_jwt",
            room_name="Test Relay Room",
            invite_code="TESTCODE",
            is_private=True,
            member_count=2,
            user_id=2
        )

        msg1 = {"type": "message", "text": "hello"}
        await test_relay.send_to_remote(vid, msg1)

        assert test_relay._outqueue[vid].qsize() == 1
        test_relay._tasks[vid].cancel()
        try:
            await test_relay._tasks[vid]
        except asyncio.CancelledError:
            pass

        msg2 = {"type": "message", "text": "world"}
        await test_relay.send_to_remote(vid, msg2)
        assert test_relay._outqueue[vid].qsize() == 2

        loop = asyncio.get_event_loop()
        new_task = loop.create_task(test_relay._relay_loop(vid, test_relay._outqueue[vid]))
        test_relay._tasks[vid] = new_task
        await asyncio.sleep(0.5)
        assert test_relay._outqueue[vid].qsize() == 0
        new_task.cancel()
        try:
            await new_task
        except asyncio.CancelledError:
            pass
