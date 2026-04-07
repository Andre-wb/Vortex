"""
Tests for key management and distribution.
"""
import secrets
import pytest

from conftest import make_user, login_user, random_str


class TestKeyManagement:

    def test_get_node_pubkey(self, client):
        resp = client.get("/api/keys/node")
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert "public_key" in data or "pubkey" in data or "key" in str(data)

    def test_get_user_pubkey(self, client, logged_user):
        user_data = logged_user["data"]
        user_id = user_data.get("id") or user_data.get("user_id")
        if user_id:
            resp = client.get(f"/api/keys/user/{user_id}", headers=logged_user["headers"])
            assert resp.status_code in (200, 404)


@pytest.mark.crypto
class TestX25519Operations:

    def test_x25519_key_generation(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes_raw()

        assert len(pub_bytes) == 32
        assert pub_bytes != b"\x00" * 32

    def test_x25519_dh_exchange(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        alice_priv = X25519PrivateKey.generate()
        bob_priv = X25519PrivateKey.generate()

        shared_alice = alice_priv.exchange(bob_priv.public_key())
        shared_bob = bob_priv.exchange(alice_priv.public_key())

        assert shared_alice == shared_bob
        assert len(shared_alice) == 32

    def test_x25519_different_keys_different_shared(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        alice = X25519PrivateKey.generate()
        bob = X25519PrivateKey.generate()
        eve = X25519PrivateKey.generate()

        shared_ab = alice.exchange(bob.public_key())
        shared_ae = alice.exchange(eve.public_key())

        assert shared_ab != shared_ae


@pytest.mark.crypto
class TestArgon2:

    def test_argon2_hash_and_verify(self):
        from app.security.crypto import hash_password, verify_password

        password = "TestPassword99!@"
        hashed = hash_password(password)

        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("WrongPassword", hashed)

    def test_argon2_different_hashes(self):
        from app.security.crypto import hash_password

        h1 = hash_password("same_password")
        h2 = hash_password("same_password")
        assert h1 != h2  # Different salt each time


@pytest.mark.crypto
class TestBLAKE3:

    def test_blake3_hash(self):
        import blake3

        data = b"vortex integrity test"
        h = blake3.blake3(data).hexdigest()
        assert len(h) == 64
        assert h == blake3.blake3(data).hexdigest()  # Deterministic

    def test_blake3_different_data(self):
        import blake3

        h1 = blake3.blake3(b"abc").hexdigest()
        h2 = blake3.blake3(b"abd").hexdigest()
        assert h1 != h2
