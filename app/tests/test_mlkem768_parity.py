from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).parent / "vectors" / "mlkem768_kat.json"

try:
    import vortex_chat as _rust
    _HAS_RUST = hasattr(_rust, "mlkem768_keygen")
except ImportError:
    _rust = None
    _HAS_RUST = False

requires_rust = pytest.mark.skipif(not _HAS_RUST, reason="vortex_chat ML-KEM не собран")

try:
    import oqs as _oqs
    _oqs.KeyEncapsulation("ML-KEM-768")
    _HAS_LIBOQS = True
except BaseException:
    _HAS_LIBOQS = False

requires_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs ML-KEM-768 недоступен")


def _vectors() -> list[dict]:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]


ALL_VECTORS = _vectors() if VECTORS_PATH.exists() else []


@requires_rust
@pytest.mark.parametrize("vec", ALL_VECTORS, ids=lambda v: v["d"][:4])
def test_derand_matches_noble(vec):
    d = bytes.fromhex(vec["d"])
    z = bytes.fromhex(vec["z"])
    m = bytes.fromhex(vec["m"])
    pk, sk = _rust.mlkem768_keygen_derand(d, z)
    ct, ss = _rust.mlkem768_encapsulate_derand(bytes(pk), m)
    assert bytes(pk).hex() == vec["ek"]
    assert bytes(sk).hex() == vec["dk"]
    assert bytes(ct).hex() == vec["ct"]
    assert bytes(ss).hex() == vec["ss"]


@requires_rust
@pytest.mark.parametrize("vec", ALL_VECTORS, ids=lambda v: v["d"][:4])
def test_derand_decapsulate_recovers_secret(vec):
    sk = bytes.fromhex(vec["dk"])
    ct = bytes.fromhex(vec["ct"])
    ss = _rust.mlkem768_decapsulate(sk, ct)
    assert bytes(ss).hex() == vec["ss"]


@requires_rust
def test_random_roundtrip_and_sizes():
    pk, sk = _rust.mlkem768_keygen()
    assert len(pk) == 1184
    assert len(sk) == 2400
    ct, ss = _rust.mlkem768_encapsulate(bytes(pk))
    assert len(ct) == 1088
    assert len(ss) == 32
    ss2 = _rust.mlkem768_decapsulate(bytes(sk), bytes(ct))
    assert bytes(ss) == bytes(ss2)


@requires_rust
def test_encapsulate_rejects_bad_public_key_length():
    with pytest.raises(ValueError):
        _rust.mlkem768_encapsulate(b"\x00" * 32)


@requires_rust
@requires_liboqs
def test_cross_decaps_rust_encaps_liboqs_decaps():
    pk, sk = _rust.mlkem768_keygen()
    ct, ss = _rust.mlkem768_encapsulate(bytes(pk))
    kem = _oqs.KeyEncapsulation("ML-KEM-768", secret_key=bytes(sk))
    assert bytes(kem.decap_secret(bytes(ct))) == bytes(ss)


@requires_rust
@requires_liboqs
def test_cross_decaps_liboqs_encaps_rust_decaps():
    kem = _oqs.KeyEncapsulation("ML-KEM-768")
    pk = bytes(kem.generate_keypair())
    sk = bytes(kem.export_secret_key())
    ct, ss = kem.encap_secret(pk)
    recovered = _rust.mlkem768_decapsulate(sk, bytes(ct))
    assert bytes(recovered) == bytes(ss)


@requires_rust
def test_hybrid_combine_matches_hkdf_sha256():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    x = b"\x11" * 32
    k = b"\x22" * 32
    info = b"vortex-pq-session-v1"
    reference = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(x + k)
    assert bytes(_rust.pq_hybrid_combine(x, k, info)) == reference


@requires_rust
def test_shim_backend_is_rust_and_roundtrips():
    from app.security import post_quantum as pq

    assert pq.pq_backend() == "rust"
    pk, sk = pq.Kyber768.keygen()
    ct, ss = pq.Kyber768.encapsulate(pk)
    assert pq.Kyber768.decapsulate(sk, ct) == ss
