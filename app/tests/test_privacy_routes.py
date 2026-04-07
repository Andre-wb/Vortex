"""
Comprehensive tests for:
  - app/security/privacy_routes.py  (all HTTP endpoints)
  - app/security/privacy.py         (unit-level: MetadataPadding, EphemeralIdentity,
                                     ZKMembership, TorProxy)

Pattern: def test_xxx(client) — uses the session-scope SyncASGIClient from conftest.
"""
import base64
import hashlib
import os
import secrets

import pytest
from conftest import make_user, login_user, random_str


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _auth(client) -> dict:
    """Register + login a fresh user, return auth headers."""
    u = make_user(client)
    h = login_user(client, u["username"], u["password"])
    return h


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ─────────────────────────────────────────────────────────────────────────────
# Privacy Status endpoint
# ─────────────────────────────────────────────────────────────────────────────

def test_privacy_status_requires_auth(anon_client):
    r = anon_client.get("/api/privacy/status")
    assert r.status_code in (401, 403)


def test_privacy_status_shape(client):
    h = _auth(client)
    r = client.get("/api/privacy/status", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert "tor" in data
    assert "metadata_padding" in data
    assert "ephemeral_identities" in data
    assert "zero_knowledge_membership" in data


def test_privacy_status_metadata_padding_details(client):
    h = _auth(client)
    data = client.get("/api/privacy/status", headers=h).json()
    mp = data["metadata_padding"]
    assert mp["enabled"] is True
    sizes = mp["standard_sizes"]
    assert 256 in sizes
    assert 4096 in sizes
    # Sizes must be sorted ascending
    assert sizes == sorted(sizes)


def test_privacy_status_ephemeral_details(client):
    h = _auth(client)
    data = client.get("/api/privacy/status", headers=h).json()
    ei = data["ephemeral_identities"]
    assert ei["enabled"] is True
    assert "HMAC" in ei["method"]


def test_privacy_status_zk_details(client):
    h = _auth(client)
    data = client.get("/api/privacy/status", headers=h).json()
    zk = data["zero_knowledge_membership"]
    assert zk["type"] == "schnorr-like-zk"
    assert "properties" in zk


# ─────────────────────────────────────────────────────────────────────────────
# Tor status endpoint
# ─────────────────────────────────────────────────────────────────────────────

def test_tor_status_requires_auth(anon_client):
    r = anon_client.get("/api/privacy/tor/status")
    assert r.status_code in (401, 403)


def test_tor_status_shape(client):
    h = _auth(client)
    r = client.get("/api/privacy/tor/status", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert "available" in data
    assert "socks_url" in data
    assert isinstance(data["available"], bool)


def test_tor_status_socks_url_format(client):
    h = _auth(client)
    data = client.get("/api/privacy/tor/status", headers=h).json()
    assert data["socks_url"].startswith("socks5://")


# ─────────────────────────────────────────────────────────────────────────────
# Ephemeral identity endpoints
# ─────────────────────────────────────────────────────────────────────────────

def test_new_ephemeral_secret_requires_auth(anon_client):
    r = anon_client.get("/api/privacy/ephemeral/new-secret")
    assert r.status_code in (401, 403)


def test_new_ephemeral_secret_returns_64_hex(client):
    h = _auth(client)
    r = client.get("/api/privacy/ephemeral/new-secret", headers=h)
    assert r.status_code == 200
    secret_hex = r.json()["secret_hex"]
    assert len(secret_hex) == 64
    # Must be valid hex
    bytes.fromhex(secret_hex)


def test_new_ephemeral_secret_is_random(client):
    h = _auth(client)
    s1 = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    s2 = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    assert s1 != s2, "Two secrets must be different (random)"


def test_ephemeral_generate_success(client):
    h = _auth(client)
    secret_hex = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    r = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 42,
        "user_secret_hex": secret_hex,
    }, headers=h)
    assert r.status_code == 200
    data = r.json()
    assert "ephemeral_username" in data
    assert "ephemeral_display_name" in data
    assert data["room_id"] == 42


def test_ephemeral_generate_username_format(client):
    h = _auth(client)
    secret_hex = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    data = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 1,
        "user_secret_hex": secret_hex,
    }, headers=h).json()
    username = data["ephemeral_username"]
    assert username.startswith("anon_"), f"Expected 'anon_' prefix, got: {username}"


def test_ephemeral_generate_display_name_has_space(client):
    h = _auth(client)
    secret_hex = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    data = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 1,
        "user_secret_hex": secret_hex,
    }, headers=h).json()
    # Display name is "Adjective Noun Number"
    assert " " in data["ephemeral_display_name"]


def test_ephemeral_generate_same_secret_same_room_deterministic(client):
    h = _auth(client)
    secret_hex = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    d1 = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 7, "user_secret_hex": secret_hex,
    }, headers=h).json()
    d2 = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 7, "user_secret_hex": secret_hex,
    }, headers=h).json()
    assert d1["ephemeral_username"] == d2["ephemeral_username"]
    assert d1["ephemeral_display_name"] == d2["ephemeral_display_name"]


def test_ephemeral_generate_different_rooms_different_names(client):
    h = _auth(client)
    secret_hex = client.get("/api/privacy/ephemeral/new-secret", headers=h).json()["secret_hex"]
    d1 = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 1, "user_secret_hex": secret_hex,
    }, headers=h).json()
    d2 = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 2, "user_secret_hex": secret_hex,
    }, headers=h).json()
    assert d1["ephemeral_username"] != d2["ephemeral_username"], \
        "Different rooms must produce different ephemeral names"


def test_ephemeral_generate_invalid_hex(client):
    h = _auth(client)
    r = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 1,
        "user_secret_hex": "not_valid_hex!",
    }, headers=h)
    assert r.status_code == 400


def test_ephemeral_generate_wrong_length_hex(client):
    """Secret must be exactly 32 bytes (64 hex chars). 31 bytes → 62 hex chars → error."""
    h = _auth(client)
    short_hex = secrets.token_hex(31)  # 62 chars, 31 bytes
    r = client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 1,
        "user_secret_hex": short_hex,
    }, headers=h)
    assert r.status_code == 400


def test_ephemeral_generate_requires_auth(anon_client):
    r = anon_client.post("/api/privacy/ephemeral/generate", json={
        "room_id": 1, "user_secret_hex": secrets.token_hex(32),
    })
    assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
# Metadata Padding endpoints
# ─────────────────────────────────────────────────────────────────────────────

def test_pad_requires_auth(anon_client):
    r = anon_client.post("/api/privacy/pad", json={"data_b64": _b64(b"x")})
    assert r.status_code in (401, 403)


def test_pad_basic(client):
    h = _auth(client)
    original = b"hello, privacy world!"
    r = client.post("/api/privacy/pad", json={"data_b64": _b64(original)}, headers=h)
    assert r.status_code == 200
    data = r.json()
    assert data["original_size"] == len(original)
    assert data["padded_size"] >= 256
    # padded_b64 must be valid base64 and decode to the announced padded_size
    padded_bytes = base64.b64decode(data["padded_b64"])
    assert len(padded_bytes) == data["padded_size"]


def test_pad_to_standard_sizes(client):
    """Padded result must land on one of the standard sizes: 256, 512, 1024 ..."""
    from app.security.privacy import MetadataPadding
    h = _auth(client)
    for size in [1, 50, 200, 500, 1000]:
        r = client.post("/api/privacy/pad", json={"data_b64": _b64(b"a" * size)}, headers=h)
        assert r.status_code == 200
        padded_size = r.json()["padded_size"]
        assert padded_size in MetadataPadding.STANDARD_SIZES, \
            f"padded_size={padded_size} not in STANDARD_SIZES for input len={size}"


def test_pad_to_fixed_target_size(client):
    h = _auth(client)
    r = client.post("/api/privacy/pad", json={
        "data_b64": _b64(b"small"),
        "target_size": 512,
    }, headers=h)
    assert r.status_code == 200
    assert r.json()["padded_size"] == 512


def test_unpad_roundtrip(client):
    h = _auth(client)
    original = b"secret message content"
    pad_resp = client.post("/api/privacy/pad", json={"data_b64": _b64(original)}, headers=h)
    padded_b64 = pad_resp.json()["padded_b64"]

    unpad_resp = client.post("/api/privacy/unpad", json={"data_b64": padded_b64}, headers=h)
    assert unpad_resp.status_code == 200
    recovered = base64.b64decode(unpad_resp.json()["data_b64"])
    assert recovered == original


def test_unpad_invalid_data(client):
    """Passing random bytes that are not valid padded format should 400."""
    h = _auth(client)
    # Only 2 bytes — too short for the 4-byte header
    short = _b64(b"\x00\x01")
    r = client.post("/api/privacy/unpad", json={"data_b64": short}, headers=h)
    assert r.status_code == 400


def test_unpad_requires_auth(anon_client):
    r = anon_client.post("/api/privacy/unpad", json={"data_b64": _b64(b"\x00" * 256)})
    assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
# ZK Membership endpoints
# ─────────────────────────────────────────────────────────────────────────────

def test_zk_info_requires_auth(anon_client):
    r = anon_client.get("/api/privacy/zk/info")
    assert r.status_code in (401, 403)


def test_zk_info_shape(client):
    h = _auth(client)
    r = client.get("/api/privacy/zk/info", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "schnorr-like-zk"
    assert data["status"] == "proof-of-concept"
    assert isinstance(data["properties"], list)
    assert len(data["properties"]) >= 3


def test_zk_challenge_requires_auth(anon_client):
    r = anon_client.post("/api/privacy/zk/challenge", json={"room_id": 1})
    assert r.status_code in (401, 403)


def test_zk_challenge_shape(client):
    h = _auth(client)
    r = client.post("/api/privacy/zk/challenge", json={"room_id": 99}, headers=h)
    assert r.status_code == 200
    data = r.json()
    assert "challenge_hex" in data
    assert data["room_id"] == 99
    # challenge must be valid 32-byte hex (64 hex chars)
    assert len(data["challenge_hex"]) == 64
    bytes.fromhex(data["challenge_hex"])


def test_zk_challenge_is_random(client):
    h = _auth(client)
    c1 = client.post("/api/privacy/zk/challenge", json={"room_id": 1}, headers=h).json()["challenge_hex"]
    c2 = client.post("/api/privacy/zk/challenge", json={"room_id": 1}, headers=h).json()["challenge_hex"]
    assert c1 != c2, "Challenges must be random per request"


def test_zk_verify_empty_room_404(client):
    """Verify against a room that has no members → 404."""
    h = _auth(client)
    commitment = secrets.token_hex(32)
    r = client.post("/api/privacy/zk/verify", json={
        "room_id": 999999,
        "commitment": commitment,
        "response": secrets.token_hex(32),
        "blinding": secrets.token_hex(32),
    }, headers=h)
    assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — MetadataPadding
# ─────────────────────────────────────────────────────────────────────────────

def test_unit_metadata_padding_small(client):
    from app.security.privacy import MetadataPadding
    data = b"hi"
    padded = MetadataPadding.pad(data)
    assert len(padded) in MetadataPadding.STANDARD_SIZES
    assert MetadataPadding.unpad(padded) == data


def test_unit_metadata_padding_empty(client):
    from app.security.privacy import MetadataPadding
    data = b""
    padded = MetadataPadding.pad(data)
    assert len(padded) in MetadataPadding.STANDARD_SIZES
    assert MetadataPadding.unpad(padded) == data


def test_unit_metadata_padding_all_standard_sizes(client):
    from app.security.privacy import MetadataPadding
    for size in MetadataPadding.STANDARD_SIZES:
        data = os.urandom(size // 2)
        padded = MetadataPadding.pad(data)
        assert len(padded) in MetadataPadding.STANDARD_SIZES
        assert MetadataPadding.unpad(padded) == data


def test_unit_metadata_padding_large_data_uses_last_bucket(client):
    from app.security.privacy import MetadataPadding
    # Data larger than the largest standard size minus header still works
    large = os.urandom(MetadataPadding.STANDARD_SIZES[-1])
    padded = MetadataPadding.pad(large)
    # Must fall back to last bucket (or equal)
    assert len(padded) >= MetadataPadding.STANDARD_SIZES[-1]


def test_unit_metadata_padding_unpad_too_short_returns_none(client):
    from app.security.privacy import MetadataPadding
    result = MetadataPadding.unpad(b"\x00\x01")  # only 2 bytes
    assert result is None


def test_unit_metadata_padding_unpad_corrupted_length_returns_none(client):
    from app.security.privacy import MetadataPadding
    # Header claims 9999 bytes but padded is only 256 bytes
    header = (9999).to_bytes(4, "big")
    padded = header + b"\x00" * 252
    result = MetadataPadding.unpad(padded)
    assert result is None


def test_unit_metadata_padding_pad_to_fixed(client):
    from app.security.privacy import MetadataPadding
    data = b"fixed size test"
    padded = MetadataPadding.pad_to_fixed(data, 512)
    assert len(padded) == 512
    assert MetadataPadding.unpad(padded) == data


def test_unit_metadata_padding_get_padded_size(client):
    from app.security.privacy import MetadataPadding
    for data_len in [0, 10, 100, 250, 510, 1020]:
        size = MetadataPadding.get_padded_size(data_len)
        assert size in MetadataPadding.STANDARD_SIZES
        assert size >= data_len + MetadataPadding.HEADER_SIZE


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — EphemeralIdentity
# ─────────────────────────────────────────────────────────────────────────────

def test_unit_ephemeral_generate_secret_length(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    assert len(secret) == 32


def test_unit_ephemeral_generate_deterministic(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    name1 = EphemeralIdentity.generate(secret, 1)
    name2 = EphemeralIdentity.generate(secret, 1)
    assert name1 == name2


def test_unit_ephemeral_generate_different_rooms(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    names = {EphemeralIdentity.generate(secret, rid) for rid in range(1, 11)}
    assert len(names) == 10, "Every room must produce a unique ephemeral name"


def test_unit_ephemeral_generate_different_secrets(client):
    from app.security.privacy import EphemeralIdentity
    s1 = EphemeralIdentity.generate_secret()
    s2 = EphemeralIdentity.generate_secret()
    assert EphemeralIdentity.generate(s1, 1) != EphemeralIdentity.generate(s2, 1)


def test_unit_ephemeral_verify_correct(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    name = EphemeralIdentity.generate(secret, 42)
    assert EphemeralIdentity.verify(secret, 42, name) is True


def test_unit_ephemeral_verify_wrong_room(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    name = EphemeralIdentity.generate(secret, 1)
    assert EphemeralIdentity.verify(secret, 2, name) is False


def test_unit_ephemeral_verify_wrong_secret(client):
    from app.security.privacy import EphemeralIdentity
    s1 = EphemeralIdentity.generate_secret()
    s2 = EphemeralIdentity.generate_secret()
    name = EphemeralIdentity.generate(s1, 1)
    assert EphemeralIdentity.verify(s2, 1, name) is False


def test_unit_ephemeral_display_name_structure(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    display = EphemeralIdentity.generate_display_name(secret, 5)
    parts = display.split(" ")
    assert len(parts) == 3, f"Expected 'Adj Noun Num', got: {display!r}"
    assert parts[2].isdigit()


def test_unit_ephemeral_display_name_range(client):
    from app.security.privacy import EphemeralIdentity
    secret = EphemeralIdentity.generate_secret()
    for room_id in range(20):
        display = EphemeralIdentity.generate_display_name(secret, room_id)
        num = int(display.split(" ")[2])
        assert 0 <= num < 100


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — ZKMembership
# ─────────────────────────────────────────────────────────────────────────────

def test_unit_zk_room_secret_length(client):
    from app.security.privacy import ZKMembership
    secret = ZKMembership.generate_room_secret()
    assert len(secret) == 32


def test_unit_zk_create_membership_token_length(client):
    from app.security.privacy import ZKMembership
    room_secret = ZKMembership.generate_room_secret()
    token = ZKMembership.create_membership_token(room_secret, 42)
    assert len(token) == 32


def test_unit_zk_token_is_deterministic(client):
    from app.security.privacy import ZKMembership
    room_secret = ZKMembership.generate_room_secret()
    t1 = ZKMembership.create_membership_token(room_secret, 7)
    t2 = ZKMembership.create_membership_token(room_secret, 7)
    assert t1 == t2


def test_unit_zk_proof_valid_member(client):
    from app.security.privacy import ZKMembership
    room_secret = ZKMembership.generate_room_secret()
    token = ZKMembership.create_membership_token(room_secret, 42)
    challenge = ZKMembership.generate_challenge()
    proof = ZKMembership.create_proof(token, challenge)
    assert ZKMembership.verify_proof(room_secret, [40, 41, 42, 43], challenge, proof)


def test_unit_zk_proof_invalid_non_member(client):
    from app.security.privacy import ZKMembership
    room_secret = ZKMembership.generate_room_secret()
    # User 99 is NOT in [1, 2, 3]
    token = ZKMembership.create_membership_token(room_secret, 99)
    challenge = ZKMembership.generate_challenge()
    proof = ZKMembership.create_proof(token, challenge)
    result = ZKMembership.verify_proof(room_secret, [1, 2, 3], challenge, proof)
    assert result is False


def test_unit_zk_proof_wrong_challenge_fails(client):
    from app.security.privacy import ZKMembership
    room_secret = ZKMembership.generate_room_secret()
    token = ZKMembership.create_membership_token(room_secret, 5)
    challenge1 = ZKMembership.generate_challenge()
    challenge2 = ZKMembership.generate_challenge()
    proof = ZKMembership.create_proof(token, challenge1)
    # Verify with wrong challenge
    result = ZKMembership.verify_proof(room_secret, [5], challenge2, proof)
    assert result is False


def test_unit_zk_proof_wrong_room_secret_fails(client):
    from app.security.privacy import ZKMembership
    rs1 = ZKMembership.generate_room_secret()
    rs2 = ZKMembership.generate_room_secret()
    token = ZKMembership.create_membership_token(rs1, 5)
    challenge = ZKMembership.generate_challenge()
    proof = ZKMembership.create_proof(token, challenge)
    # Verify with different room secret
    result = ZKMembership.verify_proof(rs2, [5], challenge, proof)
    assert result is False


def test_unit_zk_challenge_is_random(client):
    from app.security.privacy import ZKMembership
    c1 = ZKMembership.generate_challenge()
    c2 = ZKMembership.generate_challenge()
    assert c1 != c2


def test_unit_zk_get_info_fields(client):
    from app.security.privacy import ZKMembership
    info = ZKMembership.get_info()
    assert info["type"] == "schnorr-like-zk"
    assert "properties" in info
    assert "note" in info


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — TorProxy
# ─────────────────────────────────────────────────────────────────────────────

def test_unit_tor_proxy_status_shape(client):
    from app.security.privacy import TorProxy
    proxy = TorProxy()
    status = proxy.get_status()
    assert "available" in status
    assert "socks_url" in status
    assert "enabled" in status


def test_unit_tor_proxy_unavailable_in_test_env(client):
    """In CI/test environment Tor is not running."""
    from app.security.privacy import TorProxy
    proxy = TorProxy(socks_host="127.0.0.1", socks_port=9050)
    # We don't assert True/False since Tor might or might not be running;
    # we just assert it returns a bool without crashing.
    assert isinstance(proxy.is_available(), bool)


def test_unit_tor_proxy_custom_port(client):
    from app.security.privacy import TorProxy
    proxy = TorProxy(socks_host="10.0.0.1", socks_port=1234)
    assert "10.0.0.1" in proxy.socks_url
    assert "1234" in proxy.socks_url
    assert proxy.is_available() is False  # 10.0.0.1:1234 is not reachable in tests
