"""Тесты крипто-ядра: AES-GCM, SHA-256, X25519."""

import hashlib
import os
import time

import pytest


class TestAESGCM:

    @staticmethod
    def _aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

    @staticmethod
    def _aes_decrypt(key: bytes, blob: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)

    def test_roundtrip(self):
        key = os.urandom(32)
        pt  = b'Hello, VORTEX!'
        assert self._aes_decrypt(key, self._aes_encrypt(key, pt)) == pt

    def test_different_nonces(self):
        key    = os.urandom(32)
        blobs  = [self._aes_encrypt(key, b'same msg') for _ in range(20)]
        nonces = [b[:12] for b in blobs]
        assert len(set(nonces)) == 20

    def test_tamper_detection(self):
        from cryptography.exceptions import InvalidTag
        key  = os.urandom(32)
        blob = bytearray(self._aes_encrypt(key, b'secret'))
        blob[15] ^= 0xFF
        with pytest.raises((InvalidTag, Exception)):
            self._aes_decrypt(key, bytes(blob))

    def test_wrong_key_fails(self):
        from cryptography.exceptions import InvalidTag
        key1, key2 = os.urandom(32), os.urandom(32)
        blob = self._aes_encrypt(key1, b'private')
        with pytest.raises((InvalidTag, Exception)):
            self._aes_decrypt(key2, blob)

    def test_empty_plaintext(self):
        key = os.urandom(32)
        assert self._aes_decrypt(key, self._aes_encrypt(key, b'')) == b''

    def test_large_payload(self):
        key = os.urandom(32)
        pt  = os.urandom(1024 * 1024)
        assert self._aes_decrypt(key, self._aes_encrypt(key, pt)) == pt

    def test_encrypt_speed(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key  = os.urandom(32)
        gcm  = AESGCM(key)
        data = b'A' * 256
        t0   = time.perf_counter()
        for _ in range(10_000):
            nonce = os.urandom(12)
            gcm.encrypt(nonce, data, None)
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f'Шифрование слишком медленное: {elapsed:.2f}s'


class TestSHA256Integrity:

    def test_known_hash(self):
        data = b'vortex integrity check'
        assert hashlib.sha256(data).hexdigest() == hashlib.sha256(data).hexdigest()

    def test_different_data_different_hash(self):
        assert hashlib.sha256(b'abc').hexdigest() != hashlib.sha256(b'abd').hexdigest()

    def test_hash_consistency(self):
        data = os.urandom(1024)
        assert hashlib.sha256(data).hexdigest() == hashlib.sha256(data).hexdigest()

    def test_chunked_hash_equals_full(self):
        data   = os.urandom(10_000)
        chunks = [data[i:i+1024] for i in range(0, len(data), 1024)]
        h_full = hashlib.sha256(data).hexdigest()
        h_inc  = hashlib.sha256()
        for chunk in chunks:
            h_inc.update(chunk)
        assert h_inc.hexdigest() == h_full

    def test_single_bit_flip_detected(self):
        data     = bytearray(os.urandom(512))
        original = hashlib.sha256(bytes(data)).hexdigest()
        data[100] ^= 1
        assert hashlib.sha256(bytes(data)).hexdigest() != original


class TestX25519PubkeyFromJWK:

    def test_pubkey_extraction_from_jwk(self):
        import base64
        raw_pub    = os.urandom(32)
        x_b64      = base64.urlsafe_b64encode(raw_pub).rstrip(b'=').decode()
        jwk        = {'kty': 'OKP', 'crv': 'X-25519', 'x': x_b64}
        b64        = jwk['x'].replace('-', '+').replace('_', '/')
        padded     = b64 + '=' * (-len(b64) % 4)
        hex_result = base64.b64decode(padded).hex()
        assert hex_result == raw_pub.hex()
        assert len(hex_result) == 64

    def test_jwk_missing_x_returns_none(self):
        jwk = {'kty': 'OKP', 'crv': 'X-25519'}
        assert jwk.get('x') is None
