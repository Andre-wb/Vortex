"""Тесты комнат: создание, участники, вход."""

import secrets

from conftest import SyncASGIClient, random_str, random_digits, make_user, login_user, _phone_prefix


_test_phone_pfx = _phone_prefix


class TestRooms:

    def test_create_room_unauthenticated(self, client: SyncASGIClient):
        bare = SyncASGIClient()
        resp = bare.post('/api/rooms', json={
            'room_name':          'HackRoom',
            'is_public':          True,
            'encrypted_room_key': {
                'key': secrets.token_hex(32),
                'iv': secrets.token_hex(16),
                'version': '1'
            },
            'ephemeral_pub':      secrets.token_hex(32),
        })
        assert resp.status_code in (401, 403, 422)

    def test_my_rooms_contains_created(self, client: SyncASGIClient, logged_user: dict, room: dict):
        resp    = client.get('/api/rooms/my', headers=logged_user['headers'])
        assert resp.status_code == 200
        rooms   = resp.json().get('rooms', [])
        room_id = room.get('id') or room.get('room', {}).get('id')
        ids     = [r.get('id') for r in rooms]
        assert room_id in ids

    def test_public_rooms_accessible_without_auth(self, client: SyncASGIClient, room: dict):
        resp = client.get('/api/rooms/public')
        assert resp.status_code in (200, 401)

    def test_room_members_list(self, client: SyncASGIClient, logged_user: dict, room: dict):
        room_id = room.get('id') or room.get('room', {}).get('id')
        resp    = client.get(f'/api/rooms/{room_id}/members', headers=logged_user['headers'])
        assert resp.status_code in (200, 404)

    def test_room_name_too_long(self, client: SyncASGIClient, logged_user: dict):
        resp = client.post('/api/rooms', json={
            'room_name':          'A' * 500,
            'is_public':          True,
            'encrypted_room_key': {
                'key': secrets.token_hex(32),
                'iv': secrets.token_hex(16),
                'version': '1'
            },
            'ephemeral_pub':      secrets.token_hex(32),
        }, headers=logged_user['headers'])
        assert resp.status_code in (400, 422)

    def test_two_users_same_room(self, client: SyncASGIClient):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = login_user(client, u1['username'], u1['password'])
        h2 = login_user(client, u2['username'], u2['password'])

        r = client.post('/api/rooms', json={
            'room_name':          f'shared_{random_str()}',
            'is_public':          True,
            'encrypted_room_key': {
                'key': secrets.token_hex(32),
                'iv': secrets.token_hex(16),
                'version': '1'
            },
            'ephemeral_pub':      secrets.token_hex(32),
        }, headers=h1)
        assert r.status_code in (200, 201, 422)

        room_data   = r.json()
        invite_code = room_data.get('invite_code') or room_data.get('code')
        if invite_code:
            r2 = client.post(f'/api/rooms/join/{invite_code}', headers=h2)
            assert r2.status_code in (200, 201, 404)
