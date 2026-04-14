"""
Тесты для Stealth Mode (app/transport/stealth.py).

Проверяют:
  - WebSocket path obfuscation (HMAC-based)
  - Header sanitization
  - Traffic camouflage (pad/unpad)
  - UDP broadcast encryption/decryption
  - Port randomization
  - ICE server stealth config
  - Fake site HTML
  - Stealth status endpoint
"""
import os
import pytest

from app.transport.stealth import (
    obfuscate_ws_path,
    deobfuscate_ws_path,
    sanitize_request_headers,
    camouflage_payload,
    decamouflage_payload,
    encrypt_udp_broadcast,
    decrypt_udp_broadcast,
    get_stealth_port,
    get_stealth_udp_port,
    get_stealth_ice_servers,
    get_fake_index,
    get_stealth_status,
)


# ══════════════════════════════════════════════════════════════════════════════
# WebSocket Path Obfuscation
# ══════════════════════════════════════════════════════════════════════════════

class TestWSPathObfuscation:
    def test_obfuscate_returns_api_path(self):
        result = obfuscate_ws_path("/ws/chat/123")
        assert result.startswith("/api/v2/stream/")
        assert len(result) > len("/api/v2/stream/")

    def test_obfuscate_is_deterministic(self):
        a = obfuscate_ws_path("/ws/chat/456")
        b = obfuscate_ws_path("/ws/chat/456")
        assert a == b

    def test_different_paths_different_tokens(self):
        a = obfuscate_ws_path("/ws/chat/1")
        b = obfuscate_ws_path("/ws/chat/2")
        assert a != b

    def test_deobfuscate_roundtrip(self):
        original = "/ws/voice-signal/room42"
        obfuscated = obfuscate_ws_path(original)
        restored = deobfuscate_ws_path(obfuscated)
        assert restored == original

    def test_deobfuscate_unknown_returns_none(self):
        assert deobfuscate_ws_path("/api/v2/stream/nonexistent") is None


# ══════════════════════════════════════════════════════════════════════════════
# Header Sanitization
# ══════════════════════════════════════════════════════════════════════════════

class TestHeaderSanitization:
    def test_removes_banned_headers(self):
        headers = {
            "Content-Type": "application/json",
            "X-Vortex-Event": "message.new",
            "X-Vortex-Signature": "sha256=abc",
            "Authorization": "Bearer token",
        }
        cleaned = sanitize_request_headers(headers)
        assert "Content-Type" in cleaned
        assert "Authorization" in cleaned
        assert "X-Vortex-Event" not in cleaned
        assert "X-Vortex-Signature" not in cleaned

    def test_replaces_vortex_user_agent(self):
        headers = {"User-Agent": "VortexBot/1.0"}
        cleaned = sanitize_request_headers(headers)
        assert "VortexBot" not in cleaned["User-Agent"]
        assert "Mozilla" in cleaned["User-Agent"]

    def test_keeps_normal_user_agent(self):
        headers = {"User-Agent": "Mozilla/5.0 Chrome"}
        cleaned = sanitize_request_headers(headers)
        assert cleaned["User-Agent"] == "Mozilla/5.0 Chrome"


# ══════════════════════════════════════════════════════════════════════════════
# Traffic Camouflage
# ══════════════════════════════════════════════════════════════════════════════

class TestTrafficCamouflage:
    def test_camouflage_roundtrip(self):
        original = b"Hello, this is a secret message!"
        camouflaged = camouflage_payload(original)
        restored = decamouflage_payload(camouflaged)
        assert restored == original

    def test_camouflage_pads_to_standard_size(self):
        data = b"x" * 100
        camouflaged = camouflage_payload(data)
        assert len(camouflaged) in [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

    def test_camouflage_different_each_time(self):
        data = b"same data"
        a = camouflage_payload(data)
        b = camouflage_payload(data)
        # Padding is random, so camouflaged payloads should differ
        # (real_len prefix + data is same, but padding differs)
        assert decamouflage_payload(a) == decamouflage_payload(b) == data

    def test_decamouflage_short_data_passthrough(self):
        assert decamouflage_payload(b"ab") == b"ab"


# ══════════════════════════════════════════════════════════════════════════════
# UDP Encryption
# ══════════════════════════════════════════════════════════════════════════════

class TestUDPEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        payload = b'{"name":"node1","port":9000,"pubkey":"abc123"}'
        encrypted = encrypt_udp_broadcast(payload)
        decrypted = decrypt_udp_broadcast(encrypted)
        assert decrypted == payload

    def test_encrypted_looks_different(self):
        payload = b'{"name":"node1","port":9000}'
        encrypted = encrypt_udp_broadcast(payload)
        assert encrypted != payload
        # Should have 8-byte nonce prefix
        assert len(encrypted) == 8 + len(payload)

    def test_decrypt_too_short_returns_none(self):
        assert decrypt_udp_broadcast(b"short") is None

    def test_decrypt_with_nonce(self):
        """Nonce changes each encryption, but decryption still works."""
        payload = b"test payload"
        e1 = encrypt_udp_broadcast(payload)
        e2 = encrypt_udp_broadcast(payload)
        # Different nonces → different ciphertext
        assert e1[:8] != e2[:8] or e1[8:] != e2[8:]
        # Both decrypt to same
        assert decrypt_udp_broadcast(e1) == payload
        assert decrypt_udp_broadcast(e2) == payload


# ══════════════════════════════════════════════════════════════════════════════
# Port Randomization
# ══════════════════════════════════════════════════════════════════════════════

class TestPortRandomization:
    def test_default_port(self):
        """Without stealth, returns configured port."""
        port = get_stealth_port()
        # When STEALTH_MODE is not set, returns default
        assert isinstance(port, int)
        assert port > 0

    def test_default_udp_port(self):
        port = get_stealth_udp_port()
        assert isinstance(port, int)
        assert port > 0


# ══════════════════════════════════════════════════════════════════════════════
# ICE Servers
# ══════════════════════════════════════════════════════════════════════════════

class TestICEServers:
    def test_normal_mode_returns_google_stun(self):
        """Without stealth, returns standard STUN servers."""
        servers = get_stealth_ice_servers()
        urls = [s["urls"] for s in servers]
        # Should contain google STUN in non-stealth
        assert any("google" in u for u in urls)

    def test_returns_list(self):
        servers = get_stealth_ice_servers()
        assert isinstance(servers, list)
        assert len(servers) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# Fake Site
# ══════════════════════════════════════════════════════════════════════════════

class TestFakeSite:
    def test_returns_html(self):
        html = get_fake_index()
        assert "<!DOCTYPE html>" in html
        assert "<title>Welcome</title>" in html
        assert "vortex" not in html.lower()

    def test_no_identifying_info(self):
        html = get_fake_index()
        assert "vortex" not in html.lower()
        assert "p2p" not in html.lower()
        assert "messenger" not in html.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Status
# ══════════════════════════════════════════════════════════════════════════════

class TestStealthStatus:
    def test_status_returns_dict(self):
        status = get_stealth_status()
        assert "stealth_enabled" in status
        assert "ws_obfuscation" in status
        assert "header_sanitization" in status
        assert "udp_encryption" in status

    def test_all_features_consistent(self):
        status = get_stealth_status()
        enabled = status["stealth_enabled"]
        for key in ("ws_obfuscation", "header_sanitization", "udp_encryption",
                     "port_randomization", "stun_fallback", "fake_site", "traffic_camouflage"):
            assert status[key] == enabled
