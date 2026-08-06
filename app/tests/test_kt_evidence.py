"""ADR-009 Фаза 2: самопроверяемость экспортированной улики эквивокации.

Cross-impl оракул к static/js/dr/kt-evidence.js:exportEvidence/verifyEvidenceBlob.
Экспортируемый блоб — самодостаточная пара нода-подписанных утверждений; ТРЕТЬЯ
СТОРОНА (здесь Python) проверяет её БЕЗ доверия отправителю: реконструирует
vortex-kt-entry:v1-сообщение, верифицирует node_sig, сверяет sha256(account_ed_hex).
Тот же вектор, что пинит JS-тест (static/js/__tests__/kt-evidence.test.js).

КРУКС: блоб reset-НЕОДНОЗНАЧЕН (не fork-пруф) — годен для эскалации человеку, не
для автоматического бана. Это Фаза 2; строгий fork-пруф — Фаза 3 (STH/consistency).
"""

import contextlib
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_NPUB = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
_ED_OLD, _ED_NEW = "aa" * 32, "bb" * 32
_SIG_OLD = "c67bd57efd5b4461490f4fc139931247f0511d6036ff745bb586263da6a2b3b3b45f762a65a90a487fb05a65261162f5426dbd25521e3529e70d6869666af30a"
_SIG_NEW = "966dbad377d3f065f3ef6168e4501086da050d3505e65c2d21dfe1aa6a20eb2823dacb7e5e72bc527998225badd9c71197f6e6ea5d64474a6bb9479ec0de380a"


def _hash(edhex: str) -> str:
    return hashlib.sha256(edhex.encode()).hexdigest()


def _entry_message(uid, kt, h, prev, seq) -> bytes:
    return f"vortex-kt-entry:v1:{uid}:{kt}:{h}:{prev or ''}:{seq}".encode()


def _stmt(uid, edhex, seq, sig):
    return {
        "key_type": "account_ed",
        "user_id": uid,
        "pub_key_hash": _hash(edhex),
        "prev_hash": None,
        "seq": seq,
        "node_sig": sig,
        "node_pubkey": _NPUB,
        "account_ed_hex": edhex,
    }


def _sample_blob() -> str:
    # Формат ЗЕРКАЛО exportEvidence (JS): {vortex_kt_evidence, peer_user_id, reset_ambiguous, statements[]}.
    return json.dumps(
        {
            "vortex_kt_evidence": "v1",
            "peer_user_id": 1,
            "reset_ambiguous": True,
            "statements": [_stmt(1, _ED_OLD, 1, _SIG_OLD), _stmt(1, _ED_NEW, 2, _SIG_NEW)],
            "note": "self-verifiable, reset-ambiguous",
        }
    )


def _verify_blob(blob: str):
    o = json.loads(blob)
    st = o["statements"]
    assert len(st) == 2
    # Обе про ОДНОГО юзера (иначе не «пара про пира» — бессмысленная улика).
    assert st[0]["user_id"] == st[1]["user_id"] == o["peer_user_id"]
    for s in st:
        # 1. node_sig реально сходится под раздаваемым node_pubkey.
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(s["node_pubkey"])).verify(
            bytes.fromhex(s["node_sig"]),
            _entry_message(s["user_id"], s["key_type"], s["pub_key_hash"], s["prev_hash"], s["seq"]),
        )
        # 2. pub_key_hash действительно = sha256(account_ed_hex).
        assert _hash(s["account_ed_hex"]) == s["pub_key_hash"]
    return {
        "distinct_keys": st[0]["pub_key_hash"] != st[1]["pub_key_hash"],
        "same_node": st[0]["node_pubkey"] == st[1]["node_pubkey"],
    }


def test_exported_evidence_is_third_party_verifiable():
    r = _verify_blob(_sample_blob())
    assert r["distinct_keys"] is True  # два РАЗНЫХ account-Ed для одного юзера
    assert r["same_node"] is True  # один node_pubkey → не миграция ноды


def test_cross_user_pair_rejected():
    import pytest

    o = json.loads(_sample_blob())
    o["statements"][1]["user_id"] = 999  # вторая про другого юзера → не «пара про пира»
    with pytest.raises(AssertionError):
        _verify_blob(json.dumps(o))


def test_tampered_statement_fails_verification():
    o = json.loads(_sample_blob())
    o["statements"][0]["pub_key_hash"] = "cd" * 32  # подмена → node_sig не сойдётся
    with contextlib.suppress(Exception):
        _verify_blob(json.dumps(o))
        raise AssertionError("tampered blob verified")


def test_cross_impl_hash_serialization():
    # Та же деталь, что кусала на ECIES: hash = sha256 UTF-8 ХЕКС-СТРОКИ, не raw-байт.
    assert _hash(_ED_OLD) == "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    assert _hash(_ED_NEW) == "a0fab1377f49a759b57f63318262ebe89fabfc990e8e93ceac2984561482b9d4"
