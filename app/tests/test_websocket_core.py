"""Тесты WebSocket: подключение, ping/pong, структура сообщений."""

import secrets

import pytest

from conftest import random_str, random_digits, _phone_prefix
from app.main import app


_test_phone_pfx = _phone_prefix


class TestWebSocket:

    @staticmethod
    def _ws_setup(tc):
        """Регистрирует пользователя и комнату внутри TestClient, возвращает room_id."""
        tag   = random_str(8)
        phone = f'+3{int(_test_phone_pfx, 16):04d}{random_digits(7)}'
        tc.post('/api/authentication/register', json={
            'username':          f'ws_{tag}',
            'password':          'Str0ng_abcd!@',
            'display_name':      f'WS {tag}',
            'phone':             phone,
            'avatar_emoji':      '\U0001f916',
            'x25519_public_key': secrets.token_hex(32),
        })
        csrf = tc.get('/api/authentication/csrf-token').json().get('csrf_token', '')
        tc.post('/api/authentication/login', json={
            'phone_or_username': f'ws_{tag}',
            'password':          'Str0ng_abcd!@',
        }, headers={'X-CSRF-Token': csrf})
        r = tc.post('/api/rooms', json={
            'name':               f'wsroom_{tag}',
            'is_public':          True,
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext':    secrets.token_hex(60),
            },
        }, headers={'X-CSRF-Token': csrf})
        return r.json().get('id'), csrf

    def test_ws_connect_unauthenticated(self):
        """Подключение без токена закрывается с кодом 4401."""
        from starlette.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect as _WSD

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._ws_setup(tc)

        with TestClient(app, raise_server_exceptions=False) as tc_anon:
            with pytest.raises(_WSD) as exc_info:
                with tc_anon.websocket_connect(f'/ws/{room_id}') as ws:
                    ws.receive_json()
        assert exc_info.value.code == 4401

    def test_ws_connect_authenticated(self):
        """Аутентифицированный пользователь получает первичные сообщения после подключения."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._ws_setup(tc)
            with tc.websocket_connect(f'/ws/{room_id}') as ws:
                first = ws.receive_json()
                assert first.get('type') in ('room_key', 'key_request', 'history')

    def test_ws_ping_pong(self):
        """Сервер отвечает pong на ping."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._ws_setup(tc)
            with tc.websocket_connect(f'/ws/{room_id}') as ws:
                for _ in range(3):
                    ws.receive_json()
                ws.send_json({'action': 'ping'})
                pong = ws.receive_json()
                assert pong.get('type') == 'pong'

    def test_ws_message_type_structure(self):
        """История и room_key приходят сразу после подключения."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._ws_setup(tc)
            with tc.websocket_connect(f'/ws/{room_id}') as ws:
                received = [ws.receive_json() for _ in range(3)]

        types = {m.get('type') for m in received}
        assert 'history' in types, f'history не найден в {types}'
        history = next(m for m in received if m.get('type') == 'history')
        assert isinstance(history['messages'], list)
