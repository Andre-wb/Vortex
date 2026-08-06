"""Тесты E2E шифрования: ECIES, roundtrip, утечка plaintext."""

import os

import pytest


class TestE2EEncryption:

    def test_message_encrypt_decrypt_roundtrip(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        room_key = os.urandom(32)
        gcm      = AESGCM(room_key)
        for text in ['Привет!', 'Hello World', '\U0001f510 Тест', 'A' * 4096]:
            nonce   = os.urandom(12)
            ct      = gcm.encrypt(nonce, text.encode(), None)
            decoded = gcm.decrypt(nonce, ct, None).decode()
            assert decoded == text

    def test_ciphertext_not_contains_plaintext(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        room_key   = os.urandom(32)
        secret     = b'super_secret_password_12345'
        nonce      = os.urandom(12)
        ciphertext = AESGCM(room_key).encrypt(nonce, secret, None)
        assert secret not in ciphertext

    # Параметры HKDF ниже обязаны совпадать с продовым клиентом
    # (static/js/crypto.js eciesEncrypt/eciesDecrypt): salt пустой,
    # info="vortex-session". В Web Crypto salt = new Uint8Array(0); по RFC 5869
    # пустой salt эквивалентен HashLen нулей (то же даёт salt=None в
    # cryptography) — см. test_hkdf_empty_salt_matches_none ниже.

    def test_ecies_simulation(self):
        """ECIES с параметрами продового клиента (crypto.js:37-42)."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        bob_priv = X25519PrivateKey.generate()
        bob_pub  = bob_priv.public_key()
        room_key = os.urandom(32)
        eph_priv = X25519PrivateKey.generate()
        eph_pub  = eph_priv.public_key()

        shared     = eph_priv.exchange(bob_pub)
        aes_key    = HKDF(algorithm=SHA256(), length=32, salt=None, info=b'vortex-session').derive(shared)
        nonce      = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, room_key, None)

        shared2   = bob_priv.exchange(eph_pub)
        aes_key2  = HKDF(algorithm=SHA256(), length=32, salt=None, info=b'vortex-session').derive(shared2)
        recovered = AESGCM(aes_key2).decrypt(nonce, ciphertext, None)
        assert recovered == room_key

    def test_ecies_wrong_private_key_fails(self):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        bob_priv = X25519PrivateKey.generate()
        eve_priv = X25519PrivateKey.generate()
        eph_priv = X25519PrivateKey.generate()
        eph_pub  = eph_priv.public_key()
        room_key = os.urandom(32)

        shared  = eph_priv.exchange(bob_priv.public_key())
        aes_key = HKDF(SHA256(), 32, None, b'vortex-session').derive(shared)
        nonce   = os.urandom(12)
        ct      = AESGCM(aes_key).encrypt(nonce, room_key, None)

        shared_eve  = eve_priv.exchange(eph_pub)
        aes_key_eve = HKDF(SHA256(), 32, None, b'vortex-session').derive(shared_eve)
        with pytest.raises((InvalidTag, Exception)):
            AESGCM(aes_key_eve).decrypt(nonce, ct, None)

    def test_hkdf_empty_salt_matches_none(self):
        """Документирует соответствие JS↔Python: пустой salt в Web Crypto
        (new Uint8Array(0)) и salt=None в cryptography дают один ключ —
        HMAC дополняет и пустой ключ, и HashLen нулей до размера блока."""
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        ikm = os.urandom(32)
        k_none  = HKDF(SHA256(), 32, None, b'vortex-session').derive(ikm)
        k_empty = HKDF(SHA256(), 32, b'',  b'vortex-session').derive(ikm)
        k_zeros = HKDF(SHA256(), 32, b'\x00' * 32, b'vortex-session').derive(ikm)
        assert k_none == k_empty == k_zeros
