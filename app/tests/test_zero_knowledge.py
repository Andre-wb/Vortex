"""
Тесты для Zero-Knowledge API (/api/zk/*).

Проверяют:
  - Profile vault CRUD (сохранение/получение/обновление)
  - Room vault CRUD
  - Contact vault CRUD
  - Call records
  - Encrypted notifications
  - Blind search
  - Audit vault
  - ZK status endpoint
  - Blind key endpoint
  - Unauthorized access protection
"""
import secrets
import pytest

from conftest import make_user, login_user, random_str, SyncASGIClient


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _fake_vault() -> str:
    """Generate a fake encrypted vault hex string (simulates AES-GCM output)."""
    # nonce(12) + ciphertext(32) + tag(16) = 60 bytes = 120 hex chars
    return secrets.token_hex(60)


def _create_room(client: SyncASGIClient, headers: dict) -> int:
    """Create a room and return its ID."""
    r = client.post('/api/rooms', json={
        'name': f'room_{random_str()}',
        'encrypted_room_key': {
            'ephemeral_pub': secrets.token_hex(32),
            'ciphertext': secrets.token_hex(60),
        },
    }, headers=headers)
    assert r.status_code in (200, 201), f'create room failed: {r.text}'
    data = r.json()
    return data.get('room_id') or data.get('id') or data['room']['id']


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestProfileVault:
    def test_save_and_get_profile(self, client, logged_user):
        h = logged_user['headers']
        vault = _fake_vault()

        # Save
        r = client.put('/api/zk/profile', json={'vault_data': vault}, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True
        assert r.json()['version'] == 1

        # Get
        r = client.get('/api/zk/profile', headers=h)
        assert r.status_code == 200
        assert r.json()['vault_data'] == vault

    def test_update_profile_increments_version(self, client, logged_user):
        h = logged_user['headers']

        client.put('/api/zk/profile', json={'vault_data': _fake_vault()}, headers=h)
        r = client.put('/api/zk/profile', json={'vault_data': _fake_vault()}, headers=h)
        assert r.json()['version'] >= 2

    def test_get_profile_empty(self, client, logged_user):
        """New user has no vault yet — returns null."""
        # Register a completely new user to ensure empty vault
        u = make_user(client)
        h2 = login_user(client, u['username'], u['password'])
        r = client.get('/api/zk/profile', headers=h2)
        assert r.status_code == 200
        assert r.json()['vault_data'] is None

    def test_get_other_user_profile(self, client, logged_user):
        h = logged_user['headers']
        uid = logged_user['data']['user_id']

        # Save own vault first
        vault = _fake_vault()
        client.put('/api/zk/profile', json={'vault_data': vault}, headers=h)

        # Another user reads it
        u2 = make_user(client)
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get(f'/api/zk/profile/{uid}', headers=h2)
        assert r.status_code == 200
        assert r.json()['vault_data'] == vault

    def test_profile_with_blind_name(self, client, logged_user):
        h = logged_user['headers']
        blind = secrets.token_hex(32)
        r = client.put('/api/zk/profile', json={
            'vault_data': _fake_vault(),
            'blind_name': blind,
        }, headers=h)
        assert r.status_code == 200


class TestRoomVault:
    def test_save_and_get_room_vault(self, client, logged_user):
        h = logged_user['headers']
        room_id = _create_room(client, h)
        vault = _fake_vault()

        r = client.put(f'/api/zk/room/{room_id}', json={'vault_data': vault}, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True

        r = client.get(f'/api/zk/room/{room_id}', headers=h)
        assert r.status_code == 200
        assert r.json()['vault_data'] == vault

    def test_room_vault_requires_membership(self, client, logged_user):
        h = logged_user['headers']
        room_id = _create_room(client, h)

        # Another user (not a member) tries to save
        u2 = make_user(client)
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.put(f'/api/zk/room/{room_id}', json={'vault_data': _fake_vault()}, headers=h2)
        assert r.status_code == 403

    def test_room_vault_empty(self, client, logged_user):
        h = logged_user['headers']
        r = client.get('/api/zk/room/999999', headers=h)
        assert r.status_code == 200
        assert r.json()['vault_data'] is None


class TestContactVault:
    def test_save_and_list_contacts(self, client, logged_user):
        h = logged_user['headers']
        blind = secrets.token_hex(32)
        vault = _fake_vault()

        r = client.put('/api/zk/contacts', json={
            'vault_data': vault,
            'blind_id': blind,
        }, headers=h)
        assert r.status_code == 200

        r = client.get('/api/zk/contacts', headers=h)
        assert r.status_code == 200
        contacts = r.json()['contacts']
        assert any(c['blind_id'] == blind for c in contacts)

    def test_update_contact_by_blind_id(self, client, logged_user):
        h = logged_user['headers']
        blind = secrets.token_hex(32)

        # Save
        client.put('/api/zk/contacts', json={'vault_data': _fake_vault(), 'blind_id': blind}, headers=h)
        # Update (same blind_id)
        new_vault = _fake_vault()
        client.put('/api/zk/contacts', json={'vault_data': new_vault, 'blind_id': blind}, headers=h)

        r = client.get('/api/zk/contacts', headers=h)
        matching = [c for c in r.json()['contacts'] if c['blind_id'] == blind]
        assert len(matching) == 1
        assert matching[0]['vault_data'] == new_vault

    def test_delete_contact(self, client, logged_user):
        h = logged_user['headers']
        blind = secrets.token_hex(32)
        client.put('/api/zk/contacts', json={'vault_data': _fake_vault(), 'blind_id': blind}, headers=h)

        r = client.delete(f'/api/zk/contacts/{blind}', headers=h)
        assert r.status_code == 200

    def test_delete_nonexistent_contact(self, client, logged_user):
        h = logged_user['headers']
        r = client.delete(f'/api/zk/contacts/{secrets.token_hex(32)}', headers=h)
        assert r.status_code == 404


class TestCallRecords:
    def test_save_and_get_calls(self, client, logged_user):
        h = logged_user['headers']
        vault = _fake_vault()

        r = client.post('/api/zk/calls', json={'vault_data': vault}, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True

        r = client.get('/api/zk/calls', headers=h)
        assert r.status_code == 200
        records = r.json()['records']
        assert any(rec['vault_data'] == vault for rec in records)


class TestEncryptedNotifications:
    def test_push_and_get_notifications(self, client, logged_user):
        h = logged_user['headers']
        uid = logged_user['data']['user_id']

        r = client.post('/api/zk/notifications', json={
            'recipient_id': uid,
            'ephemeral_pub': secrets.token_hex(32),
            'ciphertext': secrets.token_hex(64),
        }, headers=h)
        assert r.status_code == 200

        # Get (and flush)
        r = client.get('/api/zk/notifications', headers=h)
        assert r.status_code == 200
        notifs = r.json()['notifications']
        assert len(notifs) >= 1

        # Second get — should be empty (flushed)
        r = client.get('/api/zk/notifications', headers=h)
        assert len(r.json()['notifications']) == 0


class TestBlindSearch:
    def test_blind_search_user(self, client, logged_user):
        h = logged_user['headers']
        blind = secrets.token_hex(32)

        # Save profile with blind_name
        client.put('/api/zk/profile', json={
            'vault_data': _fake_vault(),
            'blind_name': blind,
        }, headers=h)

        # Search by blind index
        r = client.post('/api/zk/search', json={
            'blind_index': blind,
            'search_type': 'user',
        }, headers=h)
        assert r.status_code == 200
        assert len(r.json()['results']) >= 1

    def test_blind_search_room(self, client, logged_user):
        h = logged_user['headers']
        room_id = _create_room(client, h)
        blind = secrets.token_hex(32)

        client.put(f'/api/zk/room/{room_id}', json={
            'vault_data': _fake_vault(),
            'blind_name': blind,
        }, headers=h)

        r = client.post('/api/zk/search', json={
            'blind_index': blind,
            'search_type': 'room',
        }, headers=h)
        assert r.status_code == 200
        assert len(r.json()['results']) >= 1

    def test_blind_search_invalid_type(self, client, logged_user):
        h = logged_user['headers']
        r = client.post('/api/zk/search', json={
            'blind_index': secrets.token_hex(32),
            'search_type': 'invalid',
        }, headers=h)
        assert r.status_code == 400


class TestAuditVault:
    def test_save_and_get_audit(self, client, logged_user):
        h = logged_user['headers']
        room_id = _create_room(client, h)
        vault = _fake_vault()

        r = client.post(f'/api/zk/audit/{room_id}', json={'vault_data': vault}, headers=h)
        assert r.status_code == 200

        r = client.get(f'/api/zk/audit/{room_id}', headers=h)
        assert r.status_code == 200
        entries = r.json()['entries']
        assert any(e['vault_data'] == vault for e in entries)

    def test_audit_requires_membership(self, client, logged_user):
        h = logged_user['headers']
        room_id = _create_room(client, h)

        u2 = make_user(client)
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get(f'/api/zk/audit/{room_id}', headers=h2)
        assert r.status_code == 403


class TestZKStatus:
    def test_zk_status(self, client, logged_user):
        h = logged_user['headers']
        r = client.get('/api/zk/status', headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data['zk_enabled'] is True
        assert 'encrypted_profiles' in data['capabilities']
        assert data['capabilities']['encrypted_profiles'] is True
        assert data['capabilities']['sealed_sender'] is True
        assert data['capabilities']['blind_search'] is True


class TestBlindKey:
    def test_get_blind_key(self, client, logged_user):
        h = logged_user['headers']
        r = client.get('/api/zk/blind-key', headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data['ok'] is True
        assert 'ephemeral_pub' in data
        assert 'ciphertext' in data
        assert len(data['ephemeral_pub']) == 64


class TestUnauthorized:
    def test_profile_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/zk/profile')
        assert r.status_code == 401

    def test_contacts_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/zk/contacts')
        assert r.status_code == 401

    def test_status_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/zk/status')
        assert r.status_code == 401
