"""
app/tests/test_key_backup.py — Tests for encrypted key backup and device linking.
"""
import secrets
import time
from unittest.mock import AsyncMock, MagicMock, patch

from conftest import make_user, login_user, random_str


# ══════════════════════════════════════════════════════════════════════════════
# Key Backup CRUD
# ══════════════════════════════════════════════════════════════════════════════

class TestKeyBackup:

    def test_upload_backup(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        vault_data = secrets.token_hex(64)   # simulated encrypted blob
        vault_salt = secrets.token_hex(32)
        r = client.post('/api/keys/backup', json={
            'vault_data': vault_data,
            'vault_salt': vault_salt,
            'kdf_params': '{"alg":"PBKDF2","iter":600000,"hash":"SHA-256"}',
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True

    def test_download_backup(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        vault_data = secrets.token_hex(64)
        vault_salt = secrets.token_hex(32)
        client.post('/api/keys/backup', json={
            'vault_data': vault_data,
            'vault_salt': vault_salt,
        }, headers=h)
        r = client.get('/api/keys/backup', headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data['vault_data'] == vault_data
        assert data['vault_salt'] == vault_salt
        assert data['version'] == 1

    def test_update_backup_increments_version(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/backup', json={
            'vault_data': secrets.token_hex(64),
            'vault_salt': secrets.token_hex(32),
        }, headers=h)
        # Update
        new_data = secrets.token_hex(64)
        client.post('/api/keys/backup', json={
            'vault_data': new_data,
            'vault_salt': secrets.token_hex(32),
        }, headers=h)
        r = client.get('/api/keys/backup', headers=h)
        assert r.json()['version'] == 2
        assert r.json()['vault_data'] == new_data

    def test_delete_backup(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/backup', json={
            'vault_data': secrets.token_hex(64),
            'vault_salt': secrets.token_hex(32),
        }, headers=h)
        r = client.delete('/api/keys/backup', headers=h)
        assert r.status_code == 200
        r2 = client.get('/api/keys/backup', headers=h)
        assert r2.status_code == 404

    def test_download_no_backup_returns_404(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/backup', headers=h)
        assert r.status_code == 404

    def test_delete_no_backup_returns_404(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.delete('/api/keys/backup', headers=h)
        assert r.status_code == 404

    def test_backup_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/keys/backup')
        assert r.status_code == 401

    def test_invalid_hex_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        # Valid length but invalid hex chars
        r = client.post('/api/keys/backup', json={
            'vault_data': 'zz' * 32,
            'vault_salt': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# Device Linking
# ══════════════════════════════════════════════════════════════════════════════

class TestDeviceLinking:

    def test_create_link_request(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        new_pub = secrets.token_hex(32)
        r = client.post('/api/keys/link/request', json={
            'new_device_pub': new_pub,
        }, headers=h)
        assert r.status_code == 200
        data = r.json()
        assert 'link_code' in data
        assert len(data['link_code']) == 6
        assert 'request_id' in data

    def test_check_link_code(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        new_pub = secrets.token_hex(32)
        r1 = client.post('/api/keys/link/request', json={
            'new_device_pub': new_pub,
        }, headers=h)
        code = r1.json()['link_code']
        r2 = client.get(f'/api/keys/link/{code}', headers=h)
        assert r2.status_code == 200
        assert r2.json()['new_device_pub'] == new_pub

    def test_approve_link_request(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        new_pub = secrets.token_hex(32)
        r1 = client.post('/api/keys/link/request', json={
            'new_device_pub': new_pub,
        }, headers=h)
        code = r1.json()['link_code']
        request_id = r1.json()['request_id']
        encrypted_keys = secrets.token_hex(128)
        r2 = client.post(f'/api/keys/link/{code}/approve', json={
            'encrypted_keys': encrypted_keys,
        }, headers=h)
        assert r2.status_code == 200
        assert r2.json()['ok'] is True

    def test_poll_approved_keys(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        new_pub = secrets.token_hex(32)
        r1 = client.post('/api/keys/link/request', json={
            'new_device_pub': new_pub,
        }, headers=h)
        code = r1.json()['link_code']
        request_id = r1.json()['request_id']
        encrypted_keys = secrets.token_hex(128)
        client.post(f'/api/keys/link/{code}/approve', json={
            'encrypted_keys': encrypted_keys,
        }, headers=h)
        # Poll
        r3 = client.get(f'/api/keys/link/poll/{request_id}', headers=h)
        assert r3.status_code == 200
        data = r3.json()
        assert data['status'] == 'approved'
        assert data['encrypted_keys'] == encrypted_keys

    def test_poll_one_time_read(self, client):
        """After first poll retrieval, keys are cleared (one-time read)."""
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        new_pub = secrets.token_hex(32)
        r1 = client.post('/api/keys/link/request', json={
            'new_device_pub': new_pub,
        }, headers=h)
        code = r1.json()['link_code']
        request_id = r1.json()['request_id']
        client.post(f'/api/keys/link/{code}/approve', json={
            'encrypted_keys': secrets.token_hex(128),
        }, headers=h)
        # First poll — gets keys
        r2 = client.get(f'/api/keys/link/poll/{request_id}', headers=h)
        assert r2.json()['status'] == 'approved'
        assert 'encrypted_keys' in r2.json()
        # Second poll — keys already consumed
        r3 = client.get(f'/api/keys/link/poll/{request_id}', headers=h)
        assert r3.json()['status'] == 'completed'
        assert 'encrypted_keys' not in r3.json()

    def test_invalid_link_code_returns_404(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/link/000000', headers=h)
        assert r.status_code == 404

    def test_link_requires_auth(self, client, anon_client):
        r = anon_client.post('/api/keys/link/request', json={
            'new_device_pub': secrets.token_hex(32),
        })
        assert r.status_code in (401, 403)

    def test_new_request_expires_old(self, client):
        """Creating a new link request expires the old one."""
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r1 = client.post('/api/keys/link/request', json={
            'new_device_pub': secrets.token_hex(32),
        }, headers=h)
        code1 = r1.json()['link_code']
        # Create second request
        client.post('/api/keys/link/request', json={
            'new_device_pub': secrets.token_hex(32),
        }, headers=h)
        # Old code should not work
        r3 = client.get(f'/api/keys/link/{code1}', headers=h)
        assert r3.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Sync Push / Pull
# ══════════════════════════════════════════════════════════════════════════════

class TestSyncPushPull:

    def test_push_sync_event(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        payload = secrets.token_hex(64)
        r = client.post('/api/keys/sync/push', json={
            'device_id': 1,
            'event_type': 'key_update',
            'payload': payload,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True
        assert r.json()['seq'] == 1

    def test_push_increments_seq(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        for i in range(3):
            r = client.post('/api/keys/sync/push', json={
                'device_id': 1,
                'event_type': 'key_update',
                'payload': secrets.token_hex(64),
            }, headers=h)
            assert r.json()['seq'] == i + 1

    def test_pull_returns_events(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        payload = secrets.token_hex(64)
        client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'key_update', 'payload': payload,
        }, headers=h)
        r = client.get('/api/keys/sync/pull?since_seq=0', headers=h)
        assert r.status_code == 200
        events = r.json()['events']
        assert len(events) >= 1
        assert events[0]['payload'] == payload
        assert events[0]['event_type'] == 'key_update'

    def test_pull_filters_by_seq(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        for _ in range(3):
            client.post('/api/keys/sync/push', json={
                'device_id': 1, 'event_type': 'key_update', 'payload': secrets.token_hex(64),
            }, headers=h)
        r = client.get('/api/keys/sync/pull?since_seq=2', headers=h)
        events = r.json()['events']
        assert len(events) == 1
        assert events[0]['seq'] == 3

    def test_pull_filters_by_event_type(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'key_update', 'payload': secrets.token_hex(64),
        }, headers=h)
        client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'history', 'payload': secrets.token_hex(64),
        }, headers=h)
        r = client.get('/api/keys/sync/pull?since_seq=0&event_type=history', headers=h)
        events = r.json()['events']
        assert len(events) == 1
        assert events[0]['event_type'] == 'history'

    def test_push_invalid_hex_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'key_update', 'payload': 'zz' * 32,
        }, headers=h)
        assert r.status_code == 400

    def test_push_invalid_event_type_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'invalid_type', 'payload': secrets.token_hex(64),
        }, headers=h)
        assert r.status_code == 422

    def test_sync_requires_auth(self, client, anon_client):
        r = anon_client.post('/api/keys/sync/push', json={
            'device_id': 1, 'event_type': 'key_update', 'payload': secrets.token_hex(64),
        })
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Cross-Signing
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossSigning:

    def test_create_cross_sign(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/cross-sign', json={
            'signer_device': 1,
            'signed_device': 2,
            'signature': secrets.token_hex(32),
            'signer_pub_hash': secrets.token_hex(32),
            'signed_pub_hash': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True

    def test_get_cross_signs(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        sig = secrets.token_hex(32)
        signer_hash = secrets.token_hex(32)
        signed_hash = secrets.token_hex(32)
        client.post('/api/keys/cross-sign', json={
            'signer_device': 1, 'signed_device': 2,
            'signature': sig, 'signer_pub_hash': signer_hash, 'signed_pub_hash': signed_hash,
        }, headers=h)
        r = client.get('/api/keys/cross-sign', headers=h)
        assert r.status_code == 200
        signs = r.json()['signs']
        assert len(signs) >= 1
        assert signs[0]['signature'] == sig
        assert signs[0]['signer_pub_hash'] == signer_hash

    def test_cross_sign_upsert(self, client):
        """Second cross-sign for same device pair updates, not duplicates."""
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/cross-sign', json={
            'signer_device': 1, 'signed_device': 2,
            'signature': secrets.token_hex(32),
            'signer_pub_hash': secrets.token_hex(32),
            'signed_pub_hash': secrets.token_hex(32),
        }, headers=h)
        new_sig = secrets.token_hex(32)
        client.post('/api/keys/cross-sign', json={
            'signer_device': 1, 'signed_device': 2,
            'signature': new_sig,
            'signer_pub_hash': secrets.token_hex(32),
            'signed_pub_hash': secrets.token_hex(32),
        }, headers=h)
        r = client.get('/api/keys/cross-sign', headers=h)
        signs = [s for s in r.json()['signs'] if s['signer_device'] == 1 and s['signed_device'] == 2]
        assert len(signs) == 1
        assert signs[0]['signature'] == new_sig

    def test_cross_sign_invalid_hex(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/cross-sign', json={
            'signer_device': 1, 'signed_device': 2,
            'signature': 'zz' * 32,
            'signer_pub_hash': secrets.token_hex(32),
            'signed_pub_hash': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 400

    def test_cross_sign_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/keys/cross-sign')
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Sync Settings
# ══════════════════════════════════════════════════════════════════════════════

class TestSyncSettings:

    def test_save_and_get_settings(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        payload = secrets.token_hex(64)
        salt = secrets.token_hex(32)
        r = client.post('/api/keys/sync/settings', json={
            'vault_data': payload,
            'vault_salt': salt,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True
        r2 = client.get('/api/keys/sync/settings', headers=h)
        assert r2.status_code == 200
        assert r2.json()['payload'] == payload

    def test_get_settings_404_when_none(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/sync/settings', headers=h)
        assert r.status_code == 404

    def test_settings_upsert(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/sync/settings', json={
            'vault_data': secrets.token_hex(64),
            'vault_salt': secrets.token_hex(32),
        }, headers=h)
        new_payload = secrets.token_hex(64)
        client.post('/api/keys/sync/settings', json={
            'vault_data': new_payload,
            'vault_salt': secrets.token_hex(32),
        }, headers=h)
        r = client.get('/api/keys/sync/settings', headers=h)
        assert r.json()['payload'] == new_payload


# ══════════════════════════════════════════════════════════════════════════════
# SSSS (Shamir's Secret Sharing)
# ══════════════════════════════════════════════════════════════════════════════

class TestSSSSSharing:

    def _make_shares(self, n=3, threshold=2):
        """Helper: generate N fake encrypted shares."""
        return [
            {
                'share_index': i + 1,
                'encrypted_share': secrets.token_hex(64),
                'recipient_id': None,
                'label': f'Contact {i + 1}',
            }
            for i in range(n)
        ]

    def test_create_ssss(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        shares = self._make_shares(3, 2)
        r = client.post('/api/keys/ssss/create', json={
            'threshold': 2,
            'total_shares': 3,
            'shares': shares,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True
        assert r.json()['threshold'] == 2
        assert r.json()['total_shares'] == 3

    def test_list_own_shares(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        shares = self._make_shares(3, 2)
        client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 3, 'shares': shares,
        }, headers=h)
        r = client.get('/api/keys/ssss/shares', headers=h)
        assert r.status_code == 200
        assert r.json()['threshold'] == 2
        assert r.json()['total_shares'] == 3
        assert len(r.json()['shares']) == 3

    def test_list_held_shares(self, client):
        """Shares where I am a recipient."""
        owner = make_user(client)
        recipient = make_user(client)
        h_owner = login_user(client, owner['username'], owner['password'])
        h_recip = login_user(client, recipient['username'], recipient['password'])
        shares = [
            {'share_index': 1, 'encrypted_share': secrets.token_hex(64),
             'recipient_id': recipient['data']['user_id'], 'label': 'r1'},
            {'share_index': 2, 'encrypted_share': secrets.token_hex(64),
             'recipient_id': None, 'label': 'r2'},
        ]
        client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 2, 'shares': shares,
        }, headers=h_owner)
        r = client.get('/api/keys/ssss/held', headers=h_recip)
        assert r.status_code == 200
        assert len(r.json()['shares']) == 1
        assert r.json()['shares'][0]['share_index'] == 1

    def test_revoke_shares(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        shares = self._make_shares(3, 2)
        client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 3, 'shares': shares,
        }, headers=h)
        r = client.delete('/api/keys/ssss', headers=h)
        assert r.status_code == 200
        assert r.json()['revoked'] == 3
        # Verify empty
        r2 = client.get('/api/keys/ssss/shares', headers=h)
        assert len(r2.json()['shares']) == 0

    def test_revoke_no_shares_404(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.delete('/api/keys/ssss', headers=h)
        assert r.status_code == 404

    def test_create_revokes_old(self, client):
        """Creating new shares revokes old set."""
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 2,
            'shares': self._make_shares(2, 2),
        }, headers=h)
        # Create new set
        client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 3,
            'shares': self._make_shares(3, 2),
        }, headers=h)
        r = client.get('/api/keys/ssss/shares', headers=h)
        assert len(r.json()['shares']) == 3

    def test_threshold_gt_total_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/ssss/create', json={
            'threshold': 5, 'total_shares': 3,
            'shares': self._make_shares(3, 5),
        }, headers=h)
        assert r.status_code == 400

    def test_wrong_share_count_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 3,
            'shares': self._make_shares(2, 2),  # only 2, expected 3
        }, headers=h)
        assert r.status_code == 400

    def test_ssss_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/keys/ssss/shares')
        assert r.status_code in (401, 403)

    def test_invalid_hex_share_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/ssss/create', json={
            'threshold': 2, 'total_shares': 2,
            'shares': [
                {'share_index': 1, 'encrypted_share': 'zz' * 32},
                {'share_index': 2, 'encrypted_share': secrets.token_hex(64)},
            ],
        }, headers=h)
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# Device Public Key (per-device fingerprint)
# ══════════════════════════════════════════════════════════════════════════════

class TestDevicePubKey:

    def test_set_device_pub_key(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        pub = secrets.token_hex(32)
        r = client.post('/api/keys/device-pub-key', json={
            'device_pub_key': pub,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True

    def test_device_pub_key_in_devices_list(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        pub = secrets.token_hex(32)
        client.post('/api/keys/device-pub-key', json={
            'device_pub_key': pub,
        }, headers=h)
        r = client.get('/api/authentication/devices', headers=h)
        devices = r.json()['devices']
        current = [d for d in devices if d.get('is_current')]
        assert len(current) >= 1
        assert current[0]['device_pub_key'] == pub

    def test_invalid_pub_key_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/device-pub-key', json={
            'device_pub_key': 'zz' * 32,
        }, headers=h)
        assert r.status_code == 400

    def test_device_pub_key_requires_auth(self, client, anon_client):
        r = anon_client.post('/api/keys/device-pub-key', json={
            'device_pub_key': secrets.token_hex(32),
        })
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Federated Backup
# ══════════════════════════════════════════════════════════════════════════════

class TestFederatedBackup:

    @staticmethod
    def _mock_push():
        """Mock _push_shard_to_peer to avoid real HTTP calls."""
        return patch("app.security.key_backup._push_shard_to_peer",
                     new_callable=AsyncMock, return_value=True)

    def _make_shards(self, n=3, threshold=2):
        return [
            {
                'shard_index': i + 1,
                'peer_ip': f'192.168.1.{10 + i}',
                'peer_port': 8000 + i,
                'encrypted_shard': secrets.token_hex(64),
                'shard_hash': secrets.token_hex(32),
            }
            for i in range(n)
        ]

    def test_distribute_shards(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        with self._mock_push():
            r = client.post('/api/keys/federated-backup/distribute', json={
                'threshold': 2, 'total_shards': 3,
                'shards': self._make_shards(3, 2),
            }, headers=h)
        assert r.status_code == 200
        assert r.json()['ok'] is True

    def test_get_status(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        with self._mock_push():
            client.post('/api/keys/federated-backup/distribute', json={
                'threshold': 2, 'total_shards': 3,
                'shards': self._make_shards(3, 2),
            }, headers=h)
        r = client.get('/api/keys/federated-backup/status', headers=h)
        assert r.status_code == 200
        assert r.json()['distributed'] is True
        assert r.json()['threshold'] == 2
        assert len(r.json()['shards']) == 3

    def test_status_empty(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/federated-backup/status', headers=h)
        assert r.json()['distributed'] is False

    def test_delete_shards(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        with self._mock_push():
            client.post('/api/keys/federated-backup/distribute', json={
                'threshold': 2, 'total_shards': 3,
                'shards': self._make_shards(3, 2),
            }, headers=h)
        r = client.delete('/api/keys/federated-backup', headers=h)
        assert r.status_code == 200
        r2 = client.get('/api/keys/federated-backup/status', headers=h)
        assert r2.json()['distributed'] is False

    def test_delete_no_shards_404(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.delete('/api/keys/federated-backup', headers=h)
        assert r.status_code == 404

    def test_store_shard_peer_endpoint(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/federated-backup/store-shard', json={
            'owner_user_id': 999,
            'shard_index': 1,
            'encrypted_shard': secrets.token_hex(64),
            'shard_hash': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 200

    def test_retrieve_shard_peer_endpoint(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/federated-backup/store-shard', json={
            'owner_user_id': 888,
            'shard_index': 1,
            'encrypted_shard': secrets.token_hex(64),
            'shard_hash': secrets.token_hex(32),
        }, headers=h)
        r = client.get('/api/keys/federated-backup/retrieve-shard/888', headers=h)
        assert r.status_code == 200
        assert len(r.json()['shards']) >= 1

    def test_retrieve_no_shards_404(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/federated-backup/retrieve-shard/777', headers=h)
        assert r.status_code == 404

    def test_threshold_gt_total_rejected(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/federated-backup/distribute', json={
            'threshold': 5, 'total_shards': 3,
            'shards': self._make_shards(3, 5),
        }, headers=h)
        assert r.status_code == 400

    def test_redistribute_replaces_old(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        with self._mock_push():
            client.post('/api/keys/federated-backup/distribute', json={
                'threshold': 2, 'total_shards': 2,
                'shards': self._make_shards(2, 2),
            }, headers=h)
            client.post('/api/keys/federated-backup/distribute', json={
                'threshold': 2, 'total_shards': 3,
                'shards': self._make_shards(3, 2),
            }, headers=h)
        r = client.get('/api/keys/federated-backup/status', headers=h)
        assert len(r.json()['shards']) == 3


# ══════════════════════════════════════════════════════════════════════════════
# Key Transparency Log
# ══════════════════════════════════════════════════════════════════════════════

class TestKeyTransparency:

    def test_log_key(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.post('/api/keys/transparency/log', json={
            'key_type': 'x25519',
            'pub_key_hash': secrets.token_hex(32),
        }, headers=h)
        assert r.status_code == 200
        assert r.json()['seq'] >= 1

    def test_get_log(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/transparency/log', json={
            'key_type': 'x25519',
            'pub_key_hash': secrets.token_hex(32),
        }, headers=h)
        uid = u['data']['user_id']
        r = client.get(f'/api/keys/transparency/{uid}', headers=h)
        assert r.status_code == 200
        # At least 1 entry (manual) + possibly 1 from registration auto-log
        assert len(r.json()['entries']) >= 1

    def test_get_latest(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        pkhash = secrets.token_hex(32)
        client.post('/api/keys/transparency/log', json={
            'key_type': 'device',
            'pub_key_hash': pkhash,
        }, headers=h)
        uid = u['data']['user_id']
        r = client.get(f'/api/keys/transparency/{uid}/latest', headers=h)
        assert r.status_code == 200
        assert r.json()['key_type'] == 'device'

    def test_audit_valid_chain(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        for _ in range(3):
            client.post('/api/keys/transparency/log', json={
                'key_type': 'x25519',
                'pub_key_hash': secrets.token_hex(32),
            }, headers=h)
        uid = u['data']['user_id']
        r = client.get(f'/api/keys/transparency/{uid}/audit', headers=h)
        assert r.status_code == 200
        assert r.json()['valid'] is True
        assert r.json()['entries'] >= 3

    def test_log_increments_seq(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r1 = client.post('/api/keys/transparency/log', json={
            'key_type': 'x25519', 'pub_key_hash': secrets.token_hex(32),
        }, headers=h)
        r2 = client.post('/api/keys/transparency/log', json={
            'key_type': 'device', 'pub_key_hash': secrets.token_hex(32),
        }, headers=h)
        assert r2.json()['seq'] > r1.json()['seq']

    def test_log_chains_prev_hash(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        client.post('/api/keys/transparency/log', json={
            'key_type': 'x25519', 'pub_key_hash': secrets.token_hex(32),
        }, headers=h)
        client.post('/api/keys/transparency/log', json={
            'key_type': 'x25519', 'pub_key_hash': secrets.token_hex(32),
        }, headers=h)
        uid = u['data']['user_id']
        r = client.get(f'/api/keys/transparency/{uid}', headers=h)
        entries = r.json()['entries']
        # Last entry should have prev_hash set
        last = [e for e in entries if e['seq'] == max(e2['seq'] for e2 in entries)][0]
        assert last['prev_hash'] is not None

    def test_latest_404_no_entries(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        # Note: registration auto-logs, so we use a high user_id
        r = client.get('/api/keys/transparency/999999/latest', headers=h)
        assert r.status_code == 404

    def test_auto_log_on_registration(self, client):
        """Registration should auto-log x25519 key to transparency."""
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        uid = u['data']['user_id']
        r = client.get(f'/api/keys/transparency/{uid}', headers=h)
        entries = r.json()['entries']
        x25519_entries = [e for e in entries if e['key_type'] == 'x25519']
        assert len(x25519_entries) >= 1

    def test_auto_log_on_device_pub_key(self, client):
        """Setting device_pub_key should auto-log to transparency."""
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        pub = secrets.token_hex(32)
        client.post('/api/keys/device-pub-key', json={
            'device_pub_key': pub,
        }, headers=h)
        uid = u['data']['user_id']
        r = client.get(f'/api/keys/transparency/{uid}', headers=h)
        entries = r.json()['entries']
        device_entries = [e for e in entries if e['key_type'] == 'device']
        assert len(device_entries) >= 1

    def test_transparency_requires_auth(self, client, anon_client):
        r = anon_client.post('/api/keys/transparency/log', json={
            'key_type': 'x25519', 'pub_key_hash': secrets.token_hex(32),
        })
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# History Export & Rooms Summary (cross-device history migration)
# ══════════════════════════════════════════════════════════════════════════════

class TestHistoryExport:

    def _create_room(self, client, headers):
        """Helper: create a test room."""
        r = client.post('/api/rooms', json={
            'name': f'room_{secrets.token_hex(4)}',
            'is_public': True,
            'encrypted_room_key': {
                'ephemeral_pub': secrets.token_hex(32),
                'ciphertext': secrets.token_hex(60),
            },
        }, headers=headers)
        assert r.status_code in (200, 201), f'create room failed: {r.text}'
        return r.json()

    def test_rooms_summary(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        self._create_room(client, h)
        r = client.get('/api/keys/sync/rooms-summary', headers=h)
        assert r.status_code == 200
        assert len(r.json()['rooms']) >= 1

    def test_rooms_summary_empty(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        r = client.get('/api/keys/sync/rooms-summary', headers=h)
        assert r.status_code == 200
        assert isinstance(r.json()['rooms'], list)

    def test_history_export_empty_room(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        room = self._create_room(client, h)
        room_id = room.get('room_id') or room.get('id')
        r = client.get(f'/api/keys/sync/history-export/{room_id}', headers=h)
        assert r.status_code == 200
        assert r.json()['room_id'] == room_id
        assert r.json()['messages'] == []
        assert r.json()['has_more'] is False

    def test_history_export_not_member(self, client):
        u1 = make_user(client)
        h1 = login_user(client, u1['username'], u1['password'])
        room = self._create_room(client, h1)
        room_id = room.get('room_id') or room.get('id')
        u2 = make_user(client)
        h2 = login_user(client, u2['username'], u2['password'])
        r = client.get(f'/api/keys/sync/history-export/{room_id}', headers=h2)
        assert r.status_code == 403

    def test_history_export_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/keys/sync/history-export/1')
        assert r.status_code in (401, 403)

    def test_rooms_summary_requires_auth(self, client, anon_client):
        r = anon_client.get('/api/keys/sync/rooms-summary')
        assert r.status_code in (401, 403)

    def test_history_export_with_limit(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        room = self._create_room(client, h)
        room_id = room.get('room_id') or room.get('id')
        r = client.get(f'/api/keys/sync/history-export/{room_id}?limit=10', headers=h)
        assert r.status_code == 200

    def test_history_export_with_before_id(self, client):
        u = make_user(client)
        h = login_user(client, u['username'], u['password'])
        room = self._create_room(client, h)
        room_id = room.get('room_id') or room.get('id')
        r = client.get(f'/api/keys/sync/history-export/{room_id}?before_id=999999', headers=h)
        assert r.status_code == 200
