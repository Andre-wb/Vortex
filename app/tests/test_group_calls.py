"""Тесты групповых звонков: start, join, decline, leave, end, status, add participant."""

import secrets

from conftest import SyncASGIClient, random_str, make_user, login_user


def _relogin(client: SyncASGIClient, user: dict) -> dict:
    """Re-login user to ensure session cookie is theirs."""
    return login_user(client, user['username'], user['password'])


def _create_room_with_two_members(client: SyncASGIClient):
    """Создаёт комнату с двумя участниками, возвращает (room_id, u1, u2).
    Session-scoped client shares cookies, so callers must _relogin() before each action."""
    u1 = make_user(client)
    u2 = make_user(client)

    # Login as u1, create room
    h1 = login_user(client, u1['username'], u1['password'])
    resp = client.post('/api/rooms', json={
        'name': f'gc_test_{random_str()}',
        'is_public': True,
        'encrypted_room_key': {
            'ephemeral_pub': secrets.token_hex(32),
            'ciphertext': secrets.token_hex(60),
        },
    }, headers=h1)
    assert resp.status_code in (200, 201), f'create room failed: {resp.text}'
    room_data = resp.json()
    room_id = room_data.get('id') or room_data.get('room', {}).get('id')
    invite_code = room_data.get('invite_code') or room_data.get('room', {}).get('invite_code')

    # Login as u2, join room
    if invite_code:
        h2 = login_user(client, u2['username'], u2['password'])
        join_resp = client.post(f'/api/rooms/join/{invite_code}', json={
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=h2)
        assert join_resp.status_code in (200, 201, 409), f'join room failed: {join_resp.text}'

    return room_id, u1, u2


class TestGroupCalls:

    def test_start_group_call(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        assert resp.status_code == 200
        data = resp.json()
        assert 'call_id' in data
        assert data['already_active'] is False
        assert data['topology'] in ('mesh', 'sfu')

    def test_start_requires_room_member(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        u3 = make_user(client)
        h3 = login_user(client, u3['username'], u3['password'])
        resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h3)
        assert resp.status_code == 403

    def test_join_group_call(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        start_resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id = start_resp.json()['call_id']

        h2 = _relogin(client, u2)
        join_resp = client.post(f'/api/group-calls/{call_id}/join', headers=h2)
        assert join_resp.status_code == 200
        data = join_resp.json()
        assert data['ok'] is True
        assert 'call' in data

    def test_decline_group_call(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        start_resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id = start_resp.json()['call_id']

        h2 = _relogin(client, u2)
        decline_resp = client.post(f'/api/group-calls/{call_id}/decline', headers=h2)
        assert decline_resp.status_code == 200
        assert decline_resp.json()['ok'] is True

    def test_leave_group_call(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        start_resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id = start_resp.json()['call_id']

        h2 = _relogin(client, u2)
        client.post(f'/api/group-calls/{call_id}/join', headers=h2)
        leave_resp = client.post(f'/api/group-calls/{call_id}/leave', headers=h2)
        assert leave_resp.status_code == 200
        assert leave_resp.json()['ok'] is True

    def test_end_group_call_by_initiator(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        start_resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id = start_resp.json()['call_id']

        end_resp = client.post(f'/api/group-calls/{call_id}/end', headers=h1)
        assert end_resp.status_code == 200
        assert end_resp.json()['ok'] is True

    def test_end_group_call_non_initiator_forbidden(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        start_resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id = start_resp.json()['call_id']

        # Re-login as u2 (non-initiator) and try to end
        h2 = _relogin(client, u2)
        end_resp = client.post(f'/api/group-calls/{call_id}/end', headers=h2)
        assert end_resp.status_code == 403

    def test_get_call_status(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        start_resp = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id = start_resp.json()['call_id']

        status_resp = client.get(f'/api/group-calls/{call_id}/status', headers=h1)
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data['call_id'] == call_id
        assert 'participants' in data
        assert data['topology'] in ('mesh', 'sfu')

    def test_get_active_call(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)

        # Start a call
        client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        active_resp = client.get(f'/api/group-calls/{room_id}/active', headers=h1)
        assert active_resp.status_code == 200
        data = active_resp.json()
        assert data['active'] is True
        assert 'call' in data

    def test_no_duplicate_active_calls(self, client: SyncASGIClient):
        room_id, u1, u2 = _create_room_with_two_members(client)
        h1 = _relogin(client, u1)
        resp1 = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h1)
        call_id1 = resp1.json()['call_id']

        h2 = _relogin(client, u2)
        resp2 = client.post(f'/api/group-calls/{room_id}/start', json={'call_type': 'group_audio'}, headers=h2)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2['already_active'] is True
        assert data2['call_id'] == call_id1
