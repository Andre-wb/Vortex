"""Кросс-языковые golden-тесты: Python и Rust обязаны совпадать байт-в-байт.

Векторы: `app/tests/vectors/rust_parity.json` (генератор
`scripts/gen_rust_parity_vectors.py`), эталоны — `app/tests/rust_parity_reference.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests.rust_parity_reference import FUNCTIONS

VECTORS_PATH = Path(__file__).parent / "vectors" / "rust_parity.json"

try:
    import vortex_chat as _rust
except ImportError:
    _rust = None

requires_rust = pytest.mark.skipif(_rust is None, reason="vortex_chat не собран")


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _cases():
    vectors = _vectors()
    for fn in FUNCTIONS:
        for index, vector in enumerate(vectors[fn.name]):
            yield pytest.param(fn, vector, id=f"{fn.name}-{index}")


ALL_CASES = list(_cases())


class TestVectorFile:
    def test_covers_every_function(self):
        assert set(_vectors()) == {fn.name for fn in FUNCTIONS}

    def test_case_count_matches_reference(self):
        vectors = _vectors()
        for fn in FUNCTIONS:
            assert len(vectors[fn.name]) == len(fn.cases), fn.name

    def test_frozen_args_match_reference(self):
        vectors = _vectors()
        for fn in FUNCTIONS:
            frozen = [v["args"] for v in vectors[fn.name]]
            assert frozen == [json.loads(json.dumps(c)) for c in fn.cases], fn.name


@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


@requires_rust
@pytest.mark.crypto
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert fn.rust(_rust, vector["args"]) == vector["expected"]


@requires_rust
@pytest.mark.crypto
class TestRoundTrip:
    """Функции со случайным выходом: проверяем взаимную обратимость."""

    def test_aes_gcm_rust_encrypt_python_decrypt(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = bytes(range(32))
        blob = bytes(_rust.encrypt_message(b"parity plaintext", key))
        assert AESGCM(key).decrypt(blob[:12], blob[12:], None) == b"parity plaintext"

    def test_aes_gcm_python_encrypt_rust_decrypt(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = bytes(range(32))
        nonce = bytes(range(12))
        blob = nonce + AESGCM(key).encrypt(nonce, b"parity plaintext", None)
        assert _rust.decrypt_message(blob, key) == "parity plaintext"

    @pytest.mark.parametrize("length", [0, 1, 62, 1000])
    def test_padding_round_trip(self, length):
        plaintext = bytes(range(256))[:1] * length
        padded = _rust.pad_to_bucket(plaintext)
        assert len(padded) == _rust.pad_bucket_for(length)
        assert _rust.unpad_from_bucket(padded) == plaintext

    def test_python_padding_unpads_in_rust(self, monkeypatch):
        from app.chats.messages import padding

        monkeypatch.setattr(padding, "_HAS_RUST_PAD", False)
        plaintext = b"cross-language padding"
        padded = padding.pad(plaintext)
        assert len(padded) == _rust.pad_bucket_for(len(plaintext))
        assert _rust.unpad_from_bucket(padded) == plaintext

    def test_rust_padding_unpads_in_python(self, monkeypatch):
        from app.chats.messages import padding

        plaintext = b"cross-language padding"
        padded = _rust.pad_to_bucket(plaintext)
        monkeypatch.setattr(padding, "_HAS_RUST_PAD", False)
        assert padding.unpad(padded) == plaintext

    def test_argon2_rust_hash_verifies_in_rust(self):
        digest = _rust.hash_password("correct horse battery staple")
        assert _rust.verify_password("correct horse battery staple", digest)
        assert not _rust.verify_password("wrong", digest)


@pytest.mark.crypto
class TestSigningCanonicalizerIsShared:
    """Подпись и проверка обязаны считать байты одной и той же функцией.

    Иначе результат зависит от того, собрано ли Rust-расширение на конкретном
    узле, а не от самого payload-а.
    """

    def test_node_and_controller_agree_on_non_ascii(self):
        from vortex_controller.controller_crypto import canonical_json

        from app.peer.controller_client import _canonical

        payload = {"name": "Мой узел", "mode": "global", "ai_capable": False}
        assert _canonical(payload) == canonical_json(payload)

    def test_handoff_token_round_trip_with_non_ascii_username(self, tmp_path):
        from app.peer.controller_client import NodeSigningKey
        from app.session import handoff_token as ht

        ht._reset_replay_cache_for_tests()
        key = NodeSigningKey.load_or_create(tmp_path / "src")
        envelope = ht.issue_handoff_token(
            signing_key=key,
            user_pubkey="aa" * 32,
            username="Алиса Петровна",
            rooms=[1, 2],
        )
        payload = ht.verify_handoff_token(envelope, lambda pubkey: pubkey == key.pubkey_hex())
        assert payload["username"] == "Алиса Петровна"


@requires_rust
@pytest.mark.crypto
class TestKnownDivergences:
    """Задокументированные расхождения canonical JSON.

    Значения не совпадают между реализациями, поэтому такие типы нельзя
    класть в подписываемые payload-ы. Тест пиннит текущее поведение обеих
    сторон: если одна из них изменится — здесь станет красно.
    """

    @pytest.mark.parametrize(
        "value,python_repr,rust_repr",
        [
            (1e-7, b'{"f":1e-07}', b'{"f":1e-7}'),
            (1e-5, b'{"f":1e-05}', b'{"f":0.00001}'),
        ],
    )
    def test_small_floats_diverge(self, value, python_repr, rust_repr):
        dumped = json.dumps({"f": value}, sort_keys=True, separators=(",", ":"))
        assert dumped.encode("utf-8") == python_repr
        assert _rust.canonical_json({"f": value}) == rust_repr

    def test_integers_beyond_i64_become_strings_in_rust(self):
        value = 2**64
        dumped = json.dumps({"i": value}, sort_keys=True, separators=(",", ":"))
        assert dumped.encode("utf-8") == b'{"i":18446744073709551616}'
        assert _rust.canonical_json({"i": value}) == b'{"i":"18446744073709551616"}'
