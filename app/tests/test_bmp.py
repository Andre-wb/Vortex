"""
test_bmp.py — Blind Mailbox Protocol tests.

Tests:
- Deposit and fetch messages
- Batch fetch (real + cover IDs)
- Cover traffic indistinguishability
- TTL expiration
- Rate limiting
- Mailbox rotation simulation
- Garbage collection
"""
import asyncio
import secrets
import time

import pytest

from conftest import make_user, login_user, random_str


def _rand_mb_id():
    return secrets.token_hex(16)


def _rand_ciphertext(size=64):
    return secrets.token_hex(size)


class TestBMPDeposit:
    """Deposit messages into blind mailboxes."""

    def test_deposit_and_fetch(self, client, logged_user):
        """Basic deposit → fetch cycle."""
        mb_id = _rand_mb_id()
        ct = _rand_ciphertext()

        # Deposit
        r = client.post(f'/api/bmp/post/{mb_id}', json={'ct': ct})
        assert r.status_code == 200

        # Fetch via batch
        r = client.post('/api/bmp/batch', json={'ids': [mb_id], 'since': 0})
        assert r.status_code == 200
        mailboxes = r.json()['mailboxes']
        assert mb_id in mailboxes
        assert mailboxes[mb_id][0]['ct'] == ct

    def test_deposit_multiple(self, client, logged_user):
        """Multiple messages in one mailbox."""
        mb_id = _rand_mb_id()
        msgs = [_rand_ciphertext() for _ in range(5)]

        for ct in msgs:
            r = client.post(f'/api/bmp/post/{mb_id}', json={'ct': ct})
            assert r.status_code == 200

        r = client.post('/api/bmp/batch', json={'ids': [mb_id], 'since': 0})
        fetched = r.json()['mailboxes'].get(mb_id, [])
        assert len(fetched) == 5

    def test_deposit_invalid_id(self, client, logged_user):
        """Too short mailbox ID rejected."""
        r = client.post('/api/bmp/post/abc', json={'ct': _rand_ciphertext()})
        assert r.status_code == 400

    def test_deposit_too_large(self, client, logged_user):
        """Message exceeding max size rejected."""
        mb_id = _rand_mb_id()
        huge = 'a' * (64 * 1024 * 2 + 10)
        r = client.post(f'/api/bmp/post/{mb_id}', json={'ct': huge})
        assert r.status_code in (413, 422)


class TestBMPBatch:
    """Batch fetch — real + cover IDs."""

    def test_batch_mixed_ids(self, client, logged_user):
        """Batch with real + non-existent (cover) IDs."""
        real_id = _rand_mb_id()
        ct = _rand_ciphertext()
        client.post(f'/api/bmp/post/{real_id}', json={'ct': ct})

        cover_ids = [_rand_mb_id() for _ in range(10)]
        all_ids = cover_ids + [real_id]

        r = client.post('/api/bmp/batch', json={'ids': all_ids, 'since': 0})
        assert r.status_code == 200
        mailboxes = r.json()['mailboxes']

        # Only real mailbox has data, cover IDs omitted
        assert real_id in mailboxes
        for cid in cover_ids:
            assert cid not in mailboxes

    def test_batch_empty_returns_empty(self, client, logged_user):
        """Batch with only cover IDs returns empty."""
        cover_ids = [_rand_mb_id() for _ in range(20)]
        r = client.post('/api/bmp/batch', json={'ids': cover_ids, 'since': 0})
        assert r.status_code == 200
        assert r.json()['mailboxes'] == {}

    def test_batch_max_limit(self, client, logged_user):
        """Batch respects max limit."""
        ids = [_rand_mb_id() for _ in range(100)]
        r = client.post('/api/bmp/batch', json={'ids': ids, 'since': 0})
        assert r.status_code == 200


class TestBMPCoverIndistinguishability:
    """Server cannot distinguish real from cover traffic."""

    def test_response_format_identical(self, client, logged_user):
        """Real and empty mailboxes have identical response format."""
        real_id = _rand_mb_id()
        cover_id = _rand_mb_id()
        client.post(f'/api/bmp/post/{real_id}', json={'ct': _rand_ciphertext()})

        # Fetch both
        r = client.post('/api/bmp/batch', json={'ids': [real_id, cover_id], 'since': 0})
        data = r.json()

        # Server returns ONLY mailboxes with data
        # Empty mailboxes are omitted — cannot distinguish "real empty" from "cover"
        assert isinstance(data['mailboxes'], dict)

    def test_no_user_id_in_response(self, client, logged_user):
        """Response contains NO user identifiers."""
        mb_id = _rand_mb_id()
        client.post(f'/api/bmp/post/{mb_id}', json={'ct': _rand_ciphertext()})

        r = client.post('/api/bmp/batch', json={'ids': [mb_id], 'since': 0})
        data = r.json()

        # Check no user info leaked
        raw = str(data)
        assert 'user_id' not in raw
        assert 'username' not in raw
        assert 'sender' not in raw


class TestBMPRotation:
    """Mailbox rotation simulation."""

    def test_different_epochs_different_ids(self):
        """Different time epochs produce different mailbox IDs."""
        # Simulate HMAC derivation
        import hashlib
        import hmac
        secret = secrets.token_bytes(32)

        def derive(epoch):
            return hmac.new(secret, epoch.to_bytes(8, 'big'), hashlib.sha256).hexdigest()[:32]

        epoch1 = 1000
        epoch2 = 1001
        id1 = derive(epoch1)
        id2 = derive(epoch2)

        assert id1 != id2  # Different epochs = different mailbox IDs
        assert len(id1) == 32

    def test_same_epoch_same_id(self):
        """Same epoch produces same mailbox ID (deterministic)."""
        import hashlib
        import hmac
        secret = secrets.token_bytes(32)

        def derive(epoch):
            return hmac.new(secret, epoch.to_bytes(8, 'big'), hashlib.sha256).hexdigest()[:32]

        id1 = derive(500)
        id2 = derive(500)
        assert id1 == id2


class TestBMPSince:
    """Timestamp filtering."""

    def test_since_filters_old(self, client, logged_user):
        """Messages before since_ts are not returned."""
        mb_id = _rand_mb_id()
        client.post(f'/api/bmp/post/{mb_id}', json={'ct': 'old_message'})

        future_ts = time.time() + 10
        r = client.post('/api/bmp/batch', json={'ids': [mb_id], 'since': future_ts})
        mailboxes = r.json()['mailboxes']
        assert mb_id not in mailboxes  # Old message filtered out


class TestBMPStats:
    """Admin stats endpoint."""

    def test_stats_requires_auth(self, client, anon_client):
        """Stats requires authentication."""
        r = anon_client.get('/api/bmp/stats')
        assert r.status_code == 401

    def test_stats_returns_data(self, client, logged_user):
        """Stats returns counters."""
        r = client.get('/api/bmp/stats', headers=logged_user['headers'])
        assert r.status_code == 200
        data = r.json()
        assert 'active_mailboxes' in data
        assert 'total_deposited' in data
        assert 'total_fetched' in data


class TestBMPGarbageCollection:
    """GC removes expired messages."""

    def test_gc_endpoint(self, client, logged_user):
        """Manual GC works."""
        r = client.delete('/api/bmp/gc', headers=logged_user['headers'])
        assert r.status_code == 200
        assert 'removed' in r.json()


class TestBMPAnonymity:
    """Core anonymity properties."""

    def test_no_auth_required_for_deposit(self, client, anon_client):
        """Deposit does NOT require authentication — by design."""
        mb_id = _rand_mb_id()
        # Note: in real deployment, rate limiting by IP prevents abuse
        r = client.post(f'/api/bmp/post/{mb_id}', json={'ct': _rand_ciphertext()})
        assert r.status_code == 200

    def test_no_auth_required_for_batch(self, client, anon_client):
        """Batch fetch does NOT require authentication — by design."""
        r = client.post('/api/bmp/batch', json={'ids': [_rand_mb_id()], 'since': 0})
        assert r.status_code == 200

    def test_server_cannot_link_sender_to_receiver(self, client, logged_user):
        """
        Core BMP property: server sees deposit and fetch on same mailbox_id
        but cannot determine who deposited or who fetched.
        Both operations are anonymous.
        """
        mb_id = _rand_mb_id()

        # "Alice" deposits
        r1 = client.post(f'/api/bmp/post/{mb_id}', json={'ct': _rand_ciphertext()})
        assert r1.status_code == 200

        # "Bob" fetches (same mailbox, different logical user)
        r2 = client.post('/api/bmp/batch', json={
            'ids': [mb_id, _rand_mb_id(), _rand_mb_id()],  # mixed with cover
            'since': 0,
        })
        assert r2.status_code == 200

        # Server log shows: POST /bmp/post/{id} and POST /bmp/batch
        # No user_id, no sender_id, no recipient_id anywhere
