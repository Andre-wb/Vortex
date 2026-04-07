"""Тесты метрик: латентность AES, пропускная способность SHA-256, ECIES цикл."""

import hashlib
import os
import time

from conftest import SyncASGIClient


class TestMetrics:

    def test_aes_encrypt_latency(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key  = os.urandom(32)
        gcm  = AESGCM(key)
        data = 'Привет, это тестовое сообщение для замера скорости!'.encode()
        timings = []
        for _ in range(1000):
            t0    = time.perf_counter()
            nonce = os.urandom(12)
            gcm.encrypt(nonce, data, None)
            timings.append((time.perf_counter() - t0) * 1000)
        avg_ms = sum(timings) / len(timings)
        p99_ms = sorted(timings)[int(len(timings) * 0.99)]
        print(f'\n  AES-256-GCM encrypt ({len(data)} байт): avg={avg_ms:.4f}ms  p99={p99_ms:.4f}ms')
        assert avg_ms < 1.0, f'avg={avg_ms:.4f}ms'
        assert p99_ms < 5.0, f'p99={p99_ms:.4f}ms'

    def test_sha256_throughput(self):
        data          = os.urandom(10 * 1024 * 1024)
        t0            = time.perf_counter()
        hashlib.sha256(data).hexdigest()
        elapsed       = time.perf_counter() - t0
        throughput_mb = (len(data) / 1024 / 1024) / elapsed
        print(f'\n  SHA-256 throughput: {throughput_mb:.1f} МБ/с')
        assert throughput_mb > 50, f'{throughput_mb:.1f} МБ/с'

    def test_ecies_full_cycle_latency(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        timings = []
        for _ in range(50):
            bob_priv      = X25519PrivateKey.generate()
            bob_pub       = bob_priv.public_key()
            room_key      = os.urandom(32)
            t0            = time.perf_counter()
            eph           = X25519PrivateKey.generate()
            eph_pub_bytes = eph.public_key().public_bytes_raw()
            shared        = eph.exchange(bob_pub)
            aes_k         = HKDF(SHA256(), 32, eph_pub_bytes, b'ecies-room-key').derive(shared)
            nonce         = os.urandom(12)
            ct            = AESGCM(aes_k).encrypt(nonce, room_key, None)
            s2            = bob_priv.exchange(eph.public_key())
            aes_k2        = HKDF(SHA256(), 32, eph_pub_bytes, b'ecies-room-key').derive(s2)
            AESGCM(aes_k2).decrypt(nonce, ct, None)
            timings.append((time.perf_counter() - t0) * 1000)
        avg_ms = sum(timings) / len(timings)
        print(f'\n  ECIES full cycle: avg={avg_ms:.2f}ms')
        assert avg_ms < 50, f'avg={avg_ms:.2f}ms'

    def test_http_api_response_time(self, client: SyncASGIClient):
        timings = []
        for _ in range(20):
            t0 = time.perf_counter()
            client.get('/api/authentication/csrf-token')
            timings.append((time.perf_counter() - t0) * 1000)
        avg_ms = sum(timings) / len(timings)
        print(f'\n  CSRF endpoint: avg={avg_ms:.1f}ms')
        assert avg_ms < 100, f'avg={avg_ms:.1f}ms'
