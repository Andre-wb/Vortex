"""Full cryptographic roundtrip tests — ECIES, AES-GCM, X25519, BLAKE3, Argon2."""
import os
import secrets
import pytest


class TestECIESFullCycle:
    """End-to-end ECIES encryption/decryption cycle."""

    def test_ecies_encrypt_decrypt_roundtrip(self):
        from app.security.key_exchange import ecies_encrypt
        from app.security.crypto import generate_x25519_keypair, derive_x25519_session_key
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Generate recipient keypair
        priv_key = X25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        pub_hex = pub_bytes.hex()

        # Encrypt
        plaintext = b"Hello, ECIES World!"
        result = ecies_encrypt(plaintext, pub_hex)
        assert "ephemeral_pub" in result
        assert "ciphertext" in result
        assert len(result["ephemeral_pub"]) == 64
        assert len(result["ciphertext"]) >= 56  # nonce(12) + min_ct + tag(16) = 28+ bytes = 56+ hex

        # Decrypt manually
        eph_pub_bytes = bytes.fromhex(result["ephemeral_pub"])
        ct_bytes = bytes.fromhex(result["ciphertext"])

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        eph_pub_key = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared = priv_key.exchange(eph_pub_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"vortex-session",
        ).derive(shared)

        nonce = ct_bytes[:12]
        encrypted = ct_bytes[12:]
        aesgcm = AESGCM(derived_key)
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
        assert decrypted == plaintext

    def test_ecies_different_plaintexts(self):
        from app.security.key_exchange import ecies_encrypt
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = X25519PrivateKey.generate()
        pub_hex = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()

        r1 = ecies_encrypt(b"Message A", pub_hex)
        r2 = ecies_encrypt(b"Message B", pub_hex)
        # Different ephemeral keys each time
        assert r1["ephemeral_pub"] != r2["ephemeral_pub"]
        assert r1["ciphertext"] != r2["ciphertext"]

    def test_ecies_empty_plaintext(self):
        from app.security.key_exchange import ecies_encrypt
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = X25519PrivateKey.generate()
        pub_hex = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()

        result = ecies_encrypt(b"", pub_hex)
        assert "ephemeral_pub" in result
        assert "ciphertext" in result

    def test_ecies_large_plaintext(self):
        from app.security.key_exchange import ecies_encrypt
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = X25519PrivateKey.generate()
        pub_hex = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()

        big_data = os.urandom(1024 * 100)  # 100 KB
        result = ecies_encrypt(big_data, pub_hex)
        assert len(result["ciphertext"]) > len(big_data) * 2

    def test_ecies_wrong_private_key_fails(self):
        from app.security.key_exchange import ecies_encrypt
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Generate two different keypairs
        priv1 = X25519PrivateKey.generate()
        pub1_hex = priv1.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()

        priv2 = X25519PrivateKey.generate()

        # Encrypt for priv1's public key
        result = ecies_encrypt(b"secret", pub1_hex)

        # Try to decrypt with priv2 — should fail
        eph_pub_bytes = bytes.fromhex(result["ephemeral_pub"])
        ct_bytes = bytes.fromhex(result["ciphertext"])

        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        wrong_shared = priv2.exchange(eph_pub)
        wrong_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"vortex-session",
        ).derive(wrong_shared)

        nonce = ct_bytes[:12]
        encrypted = ct_bytes[12:]
        aesgcm = AESGCM(wrong_key)

        with pytest.raises(Exception):
            aesgcm.decrypt(nonce, encrypted, None)


class TestAESGCMOperations:
    """AES-256-GCM encrypt/decrypt operations."""

    def test_aes_roundtrip(self):
        from app.security.crypto import generate_key, encrypt_message, decrypt_message
        key = generate_key()
        assert len(key) == 32
        plaintext = b"AES-GCM roundtrip test!"
        ct = encrypt_message(plaintext, key)
        assert ct != plaintext
        pt = decrypt_message(ct, key)
        assert pt == plaintext

    def test_aes_different_nonces(self):
        from app.security.crypto import generate_key, encrypt_message
        key = generate_key()
        ct1 = encrypt_message(b"same data", key)
        ct2 = encrypt_message(b"same data", key)
        assert ct1 != ct2  # Random nonces

    def test_aes_tamper_detected(self):
        from app.security.crypto import generate_key, encrypt_message, decrypt_message
        key = generate_key()
        ct = bytearray(encrypt_message(b"test", key))
        ct[-1] ^= 0xFF  # Flip last byte
        with pytest.raises(Exception):
            decrypt_message(bytes(ct), key)

    def test_aes_wrong_key(self):
        from app.security.crypto import generate_key, encrypt_message, decrypt_message
        key1 = generate_key()
        key2 = generate_key()
        ct = encrypt_message(b"secret", key1)
        with pytest.raises(Exception):
            decrypt_message(ct, key2)

    def test_aes_empty_plaintext(self):
        from app.security.crypto import generate_key, encrypt_message, decrypt_message
        key = generate_key()
        ct = encrypt_message(b"", key)
        pt = decrypt_message(ct, key)
        assert pt == b""

    def test_aes_binary_data(self):
        from app.security.crypto import generate_key, encrypt_message, decrypt_message
        key = generate_key()
        binary_data = os.urandom(4096)
        ct = encrypt_message(binary_data, key)
        pt = decrypt_message(ct, key)
        assert pt == binary_data


class TestX25519KeyExchange:
    """X25519 key exchange operations."""

    def test_generate_keypair_returns_32_bytes(self):
        from app.security.crypto import generate_x25519_keypair
        priv, pub = generate_x25519_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_keypair_uniqueness(self):
        from app.security.crypto import generate_x25519_keypair
        _, pub1 = generate_x25519_keypair()
        _, pub2 = generate_x25519_keypair()
        assert pub1 != pub2

    def test_dh_shared_secret_agreement(self):
        from app.security.crypto import generate_x25519_keypair, derive_x25519_session_key
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()
        shared_ab = derive_x25519_session_key(priv_a, pub_b)
        shared_ba = derive_x25519_session_key(priv_b, pub_a)
        assert shared_ab == shared_ba
        assert len(shared_ab) == 32

    def test_dh_different_peers_different_secrets(self):
        from app.security.crypto import generate_x25519_keypair, derive_x25519_session_key
        priv_a, _ = generate_x25519_keypair()
        _, pub_b = generate_x25519_keypair()
        _, pub_c = generate_x25519_keypair()
        shared_ab = derive_x25519_session_key(priv_a, pub_b)
        shared_ac = derive_x25519_session_key(priv_a, pub_c)
        assert shared_ab != shared_ac


class TestBLAKE3Hashing:
    """BLAKE3 hashing tests."""

    def test_hash_deterministic(self):
        from app.security.crypto import hash_message
        data = b"deterministic hash test"
        h1 = hash_message(data)
        h2 = hash_message(data)
        assert h1 == h2

    def test_hash_different_data(self):
        from app.security.crypto import hash_message
        h1 = hash_message(b"data A")
        h2 = hash_message(b"data B")
        assert h1 != h2

    def test_hash_empty(self):
        from app.security.crypto import hash_message
        h = hash_message(b"")
        assert len(h) > 0

    def test_hash_large_data(self):
        from app.security.crypto import hash_message
        h = hash_message(os.urandom(1024 * 1024))
        assert len(h) > 0


class TestArgon2Password:
    """Argon2id password hashing."""

    def test_hash_and_verify(self):
        from app.security.crypto import hash_password, verify_password
        pw = "TestPassword123!"
        h = hash_password(pw)
        assert h != pw
        assert verify_password(pw, h) is True

    def test_wrong_password_fails(self):
        from app.security.crypto import hash_password, verify_password
        h = hash_password("correct_password")
        assert verify_password("wrong_password", h) is False

    def test_different_salts(self):
        from app.security.crypto import hash_password
        h1 = hash_password("same_password")
        h2 = hash_password("same_password")
        assert h1 != h2  # Different salts

    def test_hash_token_and_verify(self):
        from app.security.crypto import hash_token, verify_token_hash
        token = secrets.token_hex(32)
        h = hash_token(token)
        assert verify_token_hash(token, h) is True
        assert verify_token_hash("wrong_token", h) is False


class TestNodeKeypair:
    """Node X25519 keypair persistence."""

    def test_load_or_create(self, tmp_path):
        from app.security.crypto import load_or_create_node_keypair
        priv, pub = load_or_create_node_keypair(tmp_path)
        assert len(priv) > 0
        assert len(pub) > 0
        # Load again — same keys
        priv2, pub2 = load_or_create_node_keypair(tmp_path)
        assert priv == priv2
        assert pub == pub2


class TestP2PEncryption:
    """P2P payload encryption/decryption."""

    def test_encrypt_decrypt_p2p_payload(self):
        from app.security.key_exchange import encrypt_p2p_payload, decrypt_p2p_payload
        from app.security.crypto import generate_x25519_keypair

        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()

        payload = {"room_id": 1, "sender": "alice", "message": "hello"}
        result = encrypt_p2p_payload(payload, priv_a, pub_b.hex())

        assert "ephemeral_pub" in result
        assert "ciphertext" in result

    def test_ecies_node_decrypt(self):
        from app.security.key_exchange import ecies_encrypt, ecies_decrypt_node
        from app.security.crypto import generate_x25519_keypair

        priv, pub = generate_x25519_keypair()
        plaintext = b"node-to-node secret"
        result = ecies_encrypt(plaintext, pub.hex())

        decrypted = ecies_decrypt_node(
            result["ephemeral_pub"], result["ciphertext"], priv,
        )
        assert decrypted == plaintext
