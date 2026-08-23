"""Кросс-языковые golden-тесты pre-key бандла: Python и Rust решают одинаково.

Векторы: `app/tests/vectors/proto_parity.json` (генератор
`scripts/gen_proto_parity_vectors.py`), вторая независимая реализация правил —
`app/tests/proto_parity_reference.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import proto_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "proto_parity.json"

try:
    import vortex_chat as _rust
except ImportError:
    _rust = None

requires_rust = pytest.mark.skipif(_rust is None, reason="vortex_chat не собран")


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _cases():
    vectors = _vectors()
    for fn in reference.FUNCTIONS:
        for index, vector in enumerate(vectors[fn.name]):
            yield pytest.param(fn, vector, id=f"{fn.name}-{index}")


ALL_CASES = list(_cases())


def _stored(entry: dict):
    def raw(name):
        value = entry.get(name)
        return None if value is None else bytes.fromhex(value)

    return _rust.StoredPreKeyBundle(
        identity_key=bytes.fromhex(entry["identity_key"]),
        signed_prekey=bytes.fromhex(entry["signed_prekey"]),
        signed_prekey_sig=bytes.fromhex(entry["signed_prekey_sig"]),
        signed_prekey_id=entry["signed_prekey_id"],
        device_id=entry.get("device_id"),
        identity_key_ed=raw("identity_key_ed"),
        identity_key_sig=raw("identity_key_sig"),
        supports_v2=entry.get("supports_v2"),
        device_x3dh_pub=raw("device_x3dh_pub"),
        device_sign_pub=raw("device_sign_pub"),
        device_cert_sig=raw("device_cert_sig"),
        client_device_id=entry.get("client_device_id"),
        device_kyber_pub=raw("device_kyber_pub"),
        device_kyber_sig=raw("device_kyber_sig"),
        device_kyber_id=entry.get("device_kyber_id"),
    )


def _rust_publish(args: dict) -> dict:
    parsed = _rust.prekey_parse_publish(json.dumps(args["payload"]), args["enforce"])
    if parsed.rejection is not None:
        return {"rejection": {"status": parsed.rejection.status, "detail": parsed.rejection.detail}}
    return {
        "accepted": {
            "identity_key": parsed.identity_key.hex(),
            "signed_prekey": parsed.signed_prekey.hex(),
            "signed_prekey_sig": parsed.signed_prekey_sig.hex(),
            "signed_prekey_id": parsed.signed_prekey_id,
            "identity_key_ed": None if parsed.identity_key_ed is None else parsed.identity_key_ed.hex(),
            "identity_key_sig": None if parsed.identity_key_sig is None else parsed.identity_key_sig.hex(),
            "supports_v2": parsed.supports_v2,
            "device_x3dh_pub": None if parsed.device_x3dh_pub is None else parsed.device_x3dh_pub.hex(),
            "device_sign_pub": None if parsed.device_sign_pub is None else parsed.device_sign_pub.hex(),
            "device_cert_sig": None if parsed.device_cert_sig is None else parsed.device_cert_sig.hex(),
            "device_kyber_pub": None if parsed.device_kyber_pub is None else parsed.device_kyber_pub.hex(),
            "device_kyber_sig": None if parsed.device_kyber_sig is None else parsed.device_kyber_sig.hex(),
            "device_kyber_id": parsed.device_kyber_id,
            "one_time": [[key_id, public.hex()] for key_id, public in parsed.one_time],
            "one_time_kyber": [[key_id, public.hex()] for key_id, public in parsed.one_time_kyber],
            "complaints": list(parsed.complaints),
        }
    }


def _rust_bundle_response(args: dict) -> dict:
    return _rust.prekey_bundle_response(args["user_id"], _stored(args["stored"]))


def _rust_bundle_list(args: dict) -> dict:
    return _rust.prekey_bundle_list(args["user_id"], [_stored(entry) for entry in args["stored"]])


def _rust_claim(args: dict) -> dict:
    def raw(name):
        value = args.get(name)
        return None if value is None else bytes.fromhex(value)

    return _rust.prekey_claim_response(
        one_time=raw("one_time"),
        one_time_id=args.get("one_time_id"),
        one_time_kyber=raw("one_time_kyber"),
        one_time_kyber_id=args.get("one_time_kyber_id"),
    )


def _rust_status(args: dict) -> dict:
    if not args["published"]:
        return _rust.prekey_status_unpublished()
    return _rust.prekey_status_published(args["signed_prekey_id"], args["available"], args.get("supports_v2"))


def _rust_device_id(args: dict) -> dict:
    return {"client_device_id": _rust.prekey_client_device_id(args.get("header"))}


RUST_IMPLEMENTATIONS = {
    "publish_parse": _rust_publish,
    "bundle_response": _rust_bundle_response,
    "bundle_list": _rust_bundle_list,
    "claim_response": _rust_claim,
    "status": _rust_status,
    "client_device_id": _rust_device_id,
}


class TestVectorFile:
    def test_covers_every_function(self):
        assert set(_vectors()) == {fn.name for fn in reference.FUNCTIONS}

    def test_case_count_matches_reference(self):
        vectors = _vectors()
        for fn in reference.FUNCTIONS:
            assert len(vectors[fn.name]) == len(fn.cases), fn.name

    def test_frozen_args_match_reference(self):
        vectors = _vectors()
        for fn in reference.FUNCTIONS:
            frozen = [v["args"] for v in vectors[fn.name]]
            assert frozen == [json.loads(json.dumps(c)) for c in fn.cases], fn.name

    def test_refusals_are_part_of_the_contract(self):
        refused = [v for v in _vectors()["publish_parse"] if "rejection" in v["expected"]]
        assert len(refused) >= 15
        assert all(v["expected"]["rejection"]["status"] == 400 for v in refused)


@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


@requires_rust
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


class TestPublishRules:
    def test_a_rejected_bundle_never_reports_accepted_fields(self):
        for vector in _vectors()["publish_parse"]:
            assert ("rejection" in vector["expected"]) != ("accepted" in vector["expected"])

    def test_enforcement_turns_the_same_complaint_into_a_refusal(self):
        payload = reference._bundle(identity_key_sig=None)
        warned = reference.parse_publish(payload, False)
        refused = reference.parse_publish(payload, True)
        assert warned["accepted"]["complaints"] == [refused["rejection"]["detail"]]

    def test_whitespace_inside_hex_is_not_ignored(self):
        payload = reference._bundle(identity_key="11 " * 31 + "11")
        assert reference.parse_publish(payload, True)["rejection"]["detail"] == "Invalid hex encoding in keys"

    def test_a_small_order_identity_is_refused_even_in_warn_only(self):
        payload = reference._bundle(
            identity_key=reference.FORGED_IDENTITY_KEY,
            signed_prekey=reference.FORGED_SIGNED_PREKEY,
            identity_key_ed=reference.SMALL_ORDER_ED,
            identity_key_sig=reference.ZERO_SIG,
            signed_prekey_sig=reference.ZERO_SIG,
        )
        for enforce in (True, False):
            assert reference.parse_publish(payload, enforce)["rejection"]["detail"] == ("Unusable Ed25519 identity key")


@requires_rust
class TestCrossRuntime:
    def test_rust_accepts_a_bundle_python_signed(self):
        payload = reference._bundle()
        assert reference.parse_publish(payload, True) == _rust_publish({"payload": payload, "enforce": True})

    def test_both_runtimes_refuse_the_same_forged_signature(self):
        payload = reference._bundle(signed_prekey_sig="00" * reference.ED25519_SIGNATURE_LEN)
        expected = reference.parse_publish(payload, True)
        assert "rejection" in expected
        assert _rust_publish({"payload": payload, "enforce": True}) == expected

    def test_a_published_bundle_renders_the_same_on_both_sides(self):
        payload = reference._with_kyber()
        accepted = reference.parse_publish(payload, True)["accepted"]
        stored = {
            "device_id": 11,
            "identity_key": accepted["identity_key"],
            "signed_prekey": accepted["signed_prekey"],
            "signed_prekey_sig": accepted["signed_prekey_sig"],
            "signed_prekey_id": accepted["signed_prekey_id"],
            "identity_key_ed": accepted["identity_key_ed"],
            "identity_key_sig": accepted["identity_key_sig"],
            "supports_v2": accepted["supports_v2"],
            "device_x3dh_pub": accepted["device_x3dh_pub"],
            "device_sign_pub": accepted["device_sign_pub"],
            "device_cert_sig": accepted["device_cert_sig"],
            "client_device_id": reference.CLIENT_DEVICE_ID,
            "device_kyber_pub": accepted["device_kyber_pub"],
            "device_kyber_sig": accepted["device_kyber_sig"],
            "device_kyber_id": accepted["device_kyber_id"],
        }
        assert _rust_bundle_response({"user_id": 3, "stored": stored}) == reference.bundle_response(3, stored)

    def test_both_runtimes_refuse_a_forgery_under_a_small_order_key(self):
        payload = reference._bundle(
            identity_key=reference.FORGED_IDENTITY_KEY,
            signed_prekey=reference.FORGED_SIGNED_PREKEY,
            identity_key_ed=reference.SMALL_ORDER_ED,
            identity_key_sig=reference.ZERO_SIG,
            signed_prekey_sig=reference.ZERO_SIG,
        )
        for enforce in (True, False):
            outcome = _rust_publish({"payload": payload, "enforce": enforce})
            assert outcome == reference.parse_publish(payload, enforce)
            assert outcome["rejection"]["detail"] == "Unusable Ed25519 identity key"

    def test_the_limits_python_sees_are_the_ones_rust_enforces(self):
        limits = _rust.PREKEY_LIMITS
        assert limits["max_one_time_batch"] == reference.MAX_ONE_TIME_BATCH
        assert limits["low_one_time_threshold"] == reference.LOW_ONE_TIME_THRESHOLD
        assert limits["client_device_id_len"] == reference.CLIENT_DEVICE_ID_LEN
        assert limits["kyber_public_hex_len"] == reference.KYBER_PUBLIC_LEN * 2
