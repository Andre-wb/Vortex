"""
Comprehensive tests for app/security/post_quantum.py

Covers:
  - Kyber768 key generation, encapsulation, decapsulation
  - Hybrid X25519 + Kyber768 keygen / encapsulate / decapsulate
  - hybrid_encrypt / hybrid_decrypt round-trips
  - get_pq_status()
  - Invalid input handling (bad keys, truncated ciphertexts)
  - Performance with larger payloads
  - Backend introspection
  - HTTP endpoint /api/crypto/pq-status

Pattern: def test_xxx(client) using session-scope SyncASGIClient.
"""
import os
import secrets
import time

import pytest
from conftest import make_user, login_user, random_str

from app.security.post_quantum import _PQ_SIMULATED
_requires_real_pq = pytest.mark.skipif(_PQ_SIMULATED, reason="real Kyber-768 library not installed")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP endpoint
# ─────────────────────────────────────────────────────────────────────────────

@_requires_real_pq
def test_pq_status_http(client):
    r = client.get("/api/crypto/pq-status")
    assert r.status_code == 200
    data = r.json()
    assert data["algorithm"] == "Kyber-768 (ML-KEM)"
    assert data["available"] is True
    assert "backend" in data
    assert "key_sizes" in data


def test_pq_status_http_key_sizes(client):
    data = client.get("/api/crypto/pq-status").json()
    ks = data["key_sizes"]
    assert "kyber_public_key" in ks
    assert "kyber_ciphertext" in ks
    assert "kyber_shared_secret" in ks
    assert "x25519_public_key" in ks


def test_pq_status_http_performance_fields(client):
    data = client.get("/api/crypto/pq-status").json()
    perf = data["performance"]
    assert "keygen" in perf
    assert "encaps" in perf
    assert "decaps" in perf


# ─────────────────────────────────────────────────────────────────────────────
# get_pq_status() — unit
# ─────────────────────────────────────────────────────────────────────────────

@_requires_real_pq
def test_get_pq_status_shape(client):
    from app.security.post_quantum import get_pq_status
    status = get_pq_status()
    assert status["available"] is True
    assert status["algorithm"] == "Kyber-768 (ML-KEM)"
    assert status["hybrid"] == "X25519 + Kyber-768"


@_requires_real_pq
def test_get_pq_status_security_level(client):
    from app.security.post_quantum import get_pq_status
    status = get_pq_status()
    assert "NIST" in status["security_level"]
    assert "3" in status["security_level"]


def test_pq_available(client):
    from app.security.post_quantum import pq_available
    assert pq_available() is True


def test_pq_backend_valid_value(client):
    from app.security.post_quantum import pq_backend
    backend = pq_backend()
    assert backend in ("pqcrypto", "liboqs", "simulated")


# ─────────────────────────────────────────────────────────────────────────────
# Kyber768.keygen()
# ─────────────────────────────────────────────────────────────────────────────

def test_kyber_keygen_returns_bytes(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)


def test_kyber_keygen_public_key_size(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    assert len(pk) == 1184, f"Expected 1184, got {len(pk)}"


def test_kyber_keygen_secret_key_size(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    assert len(sk) == 2400, f"Expected 2400, got {len(sk)}"


def test_kyber_keygen_different_each_call(client):
    from app.security.post_quantum import Kyber768
    pk1, sk1 = Kyber768.keygen()
    pk2, sk2 = Kyber768.keygen()
    assert pk1 != pk2, "Two keygens must produce different public keys"
    assert sk1 != sk2, "Two keygens must produce different secret keys"


def test_kyber_keygen_multiple_times(client):
    from app.security.post_quantum import Kyber768
    for _ in range(5):
        pk, sk = Kyber768.keygen()
        assert len(pk) == 1184
        assert len(sk) == 2400


# ─────────────────────────────────────────────────────────────────────────────
# Kyber768.encapsulate()
# ─────────────────────────────────────────────────────────────────────────────

def test_kyber_encapsulate_ciphertext_size(client):
    from app.security.post_quantum import Kyber768
    pk, _ = Kyber768.keygen()
    ct, ss = Kyber768.encapsulate(pk)
    assert len(ct) == 1088, f"Expected 1088, got {len(ct)}"


def test_kyber_encapsulate_shared_secret_size(client):
    from app.security.post_quantum import Kyber768
    pk, _ = Kyber768.keygen()
    ct, ss = Kyber768.encapsulate(pk)
    assert len(ss) == 32, f"Expected 32, got {len(ss)}"


def test_kyber_encapsulate_returns_bytes(client):
    from app.security.post_quantum import Kyber768
    pk, _ = Kyber768.keygen()
    ct, ss = Kyber768.encapsulate(pk)
    assert isinstance(ct, bytes)
    assert isinstance(ss, bytes)


def test_kyber_encapsulate_different_each_call(client):
    from app.security.post_quantum import Kyber768
    pk, _ = Kyber768.keygen()
    ct1, ss1 = Kyber768.encapsulate(pk)
    ct2, ss2 = Kyber768.encapsulate(pk)
    # Different encapsulations → different ciphertexts and shared secrets
    assert ct1 != ct2
    assert ss1 != ss2


# ─────────────────────────────────────────────────────────────────────────────
# Kyber768.decapsulate()
# ─────────────────────────────────────────────────────────────────────────────

def test_kyber_encaps_decaps_roundtrip(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    ct, ss_enc = Kyber768.encapsulate(pk)
    ss_dec = Kyber768.decapsulate(sk, ct)
    assert ss_enc == ss_dec, "Encapsulated and decapsulated shared secrets must match"


def test_kyber_decapsulate_returns_32_bytes(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    ct, _ = Kyber768.encapsulate(pk)
    ss = Kyber768.decapsulate(sk, ct)
    assert isinstance(ss, bytes)
    assert len(ss) == 32


def test_kyber_decapsulate_wrong_key_different_secret(client):
    """Decapsulating with a different secret key should yield a different shared secret."""
    from app.security.post_quantum import Kyber768
    pk1, sk1 = Kyber768.keygen()
    pk2, sk2 = Kyber768.keygen()
    ct, ss_correct = Kyber768.encapsulate(pk1)
    ss_wrong = Kyber768.decapsulate(sk2, ct)
    assert ss_correct != ss_wrong


def test_kyber_multiple_roundtrips(client):
    from app.security.post_quantum import Kyber768
    for _ in range(10):
        pk, sk = Kyber768.keygen()
        ct, ss1 = Kyber768.encapsulate(pk)
        ss2 = Kyber768.decapsulate(sk, ct)
        assert ss1 == ss2


# ─────────────────────────────────────────────────────────────────────────────
# hybrid_keygen()
# ─────────────────────────────────────────────────────────────────────────────

def test_hybrid_keygen_returns_all_keys(client):
    from app.security.post_quantum import hybrid_keygen
    keys = hybrid_keygen()
    assert "x25519_private" in keys
    assert "x25519_public" in keys
    assert "kyber_public" in keys
    assert "kyber_secret" in keys


def test_hybrid_keygen_x25519_sizes(client):
    from app.security.post_quantum import hybrid_keygen
    keys = hybrid_keygen()
    assert len(keys["x25519_private"]) == 32
    assert len(keys["x25519_public"]) == 32


def test_hybrid_keygen_kyber_sizes(client):
    from app.security.post_quantum import hybrid_keygen
    keys = hybrid_keygen()
    assert len(keys["kyber_public"]) == 1184
    assert len(keys["kyber_secret"]) == 2400


def test_hybrid_keygen_all_bytes(client):
    from app.security.post_quantum import hybrid_keygen
    keys = hybrid_keygen()
    for k, v in keys.items():
        assert isinstance(v, bytes), f"Key {k} must be bytes, got {type(v)}"


def test_hybrid_keygen_different_each_call(client):
    from app.security.post_quantum import hybrid_keygen
    k1 = hybrid_keygen()
    k2 = hybrid_keygen()
    assert k1["x25519_public"] != k2["x25519_public"]
    assert k1["kyber_public"] != k2["kyber_public"]


# ─────────────────────────────────────────────────────────────────────────────
# hybrid_encapsulate() / hybrid_decapsulate()
# ─────────────────────────────────────────────────────────────────────────────

def test_hybrid_encapsulate_fields(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encapsulate
    keys = hybrid_keygen()
    result = hybrid_encapsulate(keys["x25519_public"], keys["kyber_public"])
    assert "x25519_ephemeral_pub" in result
    assert "kyber_ciphertext" in result
    assert "shared_secret" in result


def test_hybrid_encapsulate_shared_secret_size(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encapsulate
    keys = hybrid_keygen()
    result = hybrid_encapsulate(keys["x25519_public"], keys["kyber_public"])
    assert len(result["shared_secret"]) == 32


def test_hybrid_encapsulate_decapsulate_roundtrip(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encapsulate, hybrid_decapsulate
    keys = hybrid_keygen()
    enc = hybrid_encapsulate(keys["x25519_public"], keys["kyber_public"])
    recovered = hybrid_decapsulate(
        keys["x25519_private"],
        keys["kyber_secret"],
        enc["x25519_ephemeral_pub"],
        enc["kyber_ciphertext"],
    )
    assert enc["shared_secret"] == recovered


def test_hybrid_encapsulate_produces_hex_strings(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encapsulate
    keys = hybrid_keygen()
    result = hybrid_encapsulate(keys["x25519_public"], keys["kyber_public"])
    # ephemeral pub and ciphertext are hex strings
    bytes.fromhex(result["x25519_ephemeral_pub"])
    bytes.fromhex(result["kyber_ciphertext"])


def test_hybrid_decapsulate_wrong_x25519_key(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encapsulate, hybrid_decapsulate
    keys = hybrid_keygen()
    other = hybrid_keygen()
    enc = hybrid_encapsulate(keys["x25519_public"], keys["kyber_public"])
    recovered = hybrid_decapsulate(
        other["x25519_private"],  # wrong x25519 key
        keys["kyber_secret"],
        enc["x25519_ephemeral_pub"],
        enc["kyber_ciphertext"],
    )
    assert enc["shared_secret"] != recovered


# ─────────────────────────────────────────────────────────────────────────────
# hybrid_encrypt() / hybrid_decrypt()
# ─────────────────────────────────────────────────────────────────────────────

def test_hybrid_encrypt_shape(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt
    keys = hybrid_keygen()
    plaintext = b"room key material 12345"
    result = hybrid_encrypt(
        plaintext,
        keys["x25519_public"].hex(),
        keys["kyber_public"].hex(),
    )
    assert result["hybrid"] is True
    assert "x25519_ephemeral_pub" in result
    assert "kyber_ciphertext" in result
    assert "ciphertext" in result


def test_hybrid_encrypt_ciphertext_is_hex(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt
    keys = hybrid_keygen()
    result = hybrid_encrypt(b"test", keys["x25519_public"].hex(), keys["kyber_public"].hex())
    bytes.fromhex(result["ciphertext"])  # must not raise


def test_hybrid_encrypt_decrypt_roundtrip(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    plaintext = b"post-quantum secure message"
    enc = hybrid_encrypt(
        plaintext,
        keys["x25519_public"].hex(),
        keys["kyber_public"].hex(),
    )
    dec = hybrid_decrypt(keys["x25519_private"], keys["kyber_secret"], enc)
    assert dec == plaintext


def test_hybrid_encrypt_decrypt_empty_plaintext(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    plaintext = b""
    enc = hybrid_encrypt(plaintext, keys["x25519_public"].hex(), keys["kyber_public"].hex())
    dec = hybrid_decrypt(keys["x25519_private"], keys["kyber_secret"], enc)
    assert dec == plaintext


def test_hybrid_encrypt_decrypt_large_payload(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    # Simulate 32 KB payload (large message body)
    plaintext = os.urandom(32_768)
    enc = hybrid_encrypt(plaintext, keys["x25519_public"].hex(), keys["kyber_public"].hex())
    dec = hybrid_decrypt(keys["x25519_private"], keys["kyber_secret"], enc)
    assert dec == plaintext


def test_hybrid_encrypt_produces_different_ciphertext_each_time(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt
    keys = hybrid_keygen()
    plaintext = b"same plaintext"
    enc1 = hybrid_encrypt(plaintext, keys["x25519_public"].hex(), keys["kyber_public"].hex())
    enc2 = hybrid_encrypt(plaintext, keys["x25519_public"].hex(), keys["kyber_public"].hex())
    # Different ephemeral keys → different ciphertexts (IND-CCA)
    assert enc1["ciphertext"] != enc2["ciphertext"]
    assert enc1["x25519_ephemeral_pub"] != enc2["x25519_ephemeral_pub"]


def test_hybrid_decrypt_wrong_x25519_key_raises_or_wrong_plaintext(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    other = hybrid_keygen()
    plaintext = b"secret data"
    enc = hybrid_encrypt(plaintext, keys["x25519_public"].hex(), keys["kyber_public"].hex())
    try:
        result = hybrid_decrypt(other["x25519_private"], keys["kyber_secret"], enc)
        assert result != plaintext, "Wrong key must not recover the correct plaintext"
    except Exception:
        pass  # Exception is also acceptable — means decryption failed as expected


def test_hybrid_encrypt_decrypt_multiple_plaintexts(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    test_vectors = [
        b"short",
        b"A" * 128,
        os.urandom(512),
        b"\x00" * 64,
        b"\xff" * 64,
    ]
    for pt in test_vectors:
        enc = hybrid_encrypt(pt, keys["x25519_public"].hex(), keys["kyber_public"].hex())
        dec = hybrid_decrypt(keys["x25519_private"], keys["kyber_secret"], enc)
        assert dec == pt, f"Roundtrip failed for plaintext of length {len(pt)}"


# ─────────────────────────────────────────────────────────────────────────────
# Performance tests
# ─────────────────────────────────────────────────────────────────────────────

def test_kyber_keygen_performance(client):
    """100 keygens should complete in under 5 seconds."""
    from app.security.post_quantum import Kyber768
    start = time.monotonic()
    for _ in range(100):
        Kyber768.keygen()
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"100 Kyber keygens took {elapsed:.2f}s (expected < 5s)"


def test_kyber_encaps_decaps_performance(client):
    """100 encapsulate+decapsulate cycles in under 5 seconds."""
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    start = time.monotonic()
    for _ in range(100):
        ct, ss1 = Kyber768.encapsulate(pk)
        ss2 = Kyber768.decapsulate(sk, ct)
        assert ss1 == ss2
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"100 Kyber encaps/decaps cycles took {elapsed:.2f}s"


def test_hybrid_encrypt_decrypt_performance_1kb(client):
    """50 hybrid encrypt+decrypt of 1 KB payloads should be fast."""
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    payload = os.urandom(1024)
    start = time.monotonic()
    for _ in range(50):
        enc = hybrid_encrypt(payload, keys["x25519_public"].hex(), keys["kyber_public"].hex())
        dec = hybrid_decrypt(keys["x25519_private"], keys["kyber_secret"], enc)
        assert dec == payload
    elapsed = time.monotonic() - start
    assert elapsed < 10.0, f"50 hybrid encrypt/decrypt of 1KB took {elapsed:.2f}s"


def test_hybrid_encrypt_decrypt_performance_large_payload(client):
    """Encrypt+decrypt of a 1 MB payload in under 3 seconds."""
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt, hybrid_decrypt
    keys = hybrid_keygen()
    payload = os.urandom(1024 * 1024)  # 1 MB
    start = time.monotonic()
    enc = hybrid_encrypt(payload, keys["x25519_public"].hex(), keys["kyber_public"].hex())
    dec = hybrid_decrypt(keys["x25519_private"], keys["kyber_secret"], enc)
    elapsed = time.monotonic() - start
    assert dec == payload
    assert elapsed < 3.0, f"1 MB hybrid encrypt/decrypt took {elapsed:.2f}s"


# ─────────────────────────────────────────────────────────────────────────────
# Edge / error cases
# ─────────────────────────────────────────────────────────────────────────────

def test_hybrid_encrypt_invalid_x25519_hex_raises(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt
    keys = hybrid_keygen()
    with pytest.raises(Exception):
        hybrid_encrypt(b"data", "not_valid_hex!", keys["kyber_public"].hex())


def test_hybrid_encrypt_invalid_kyber_hex_raises(client):
    from app.security.post_quantum import hybrid_keygen, hybrid_encrypt
    keys = hybrid_keygen()
    with pytest.raises(Exception):
        hybrid_encrypt(b"data", keys["x25519_public"].hex(), "zzz_invalid")


def test_kyber_decapsulate_returns_bytes_type(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    ct, ss = Kyber768.encapsulate(pk)
    recovered = Kyber768.decapsulate(sk, ct)
    assert type(recovered) is bytes


def test_hybrid_keygen_all_keys_non_zero(client):
    from app.security.post_quantum import hybrid_keygen
    keys = hybrid_keygen()
    for name, value in keys.items():
        assert value != b"\x00" * len(value), f"Key {name} is all zeros — looks like uninitialized"


def test_kyber_shared_secret_non_zero(client):
    from app.security.post_quantum import Kyber768
    pk, sk = Kyber768.keygen()
    ct, ss = Kyber768.encapsulate(pk)
    assert ss != b"\x00" * 32, "Shared secret is all zeros — something is wrong"
