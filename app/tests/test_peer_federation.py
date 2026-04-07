"""Peer registry and federation tests."""
import secrets
import pytest
from conftest import make_user, login_user, random_str


class TestPeerRegistry:
    """Peer registry unit tests."""

    def test_peer_info_creation(self):
        from app.peer.peer_registry import PeerInfo
        peer = PeerInfo(
            name="test-node",
            ip="192.168.1.100",
            port=9000,
            node_pubkey_hex=secrets.token_hex(32),
        )
        assert peer.name == "test-node"
        assert peer.ip == "192.168.1.100"
        assert peer.port == 9000
        assert peer.alive() is True

    def test_peer_info_to_dict(self):
        from app.peer.peer_registry import PeerInfo
        peer = PeerInfo(name="node", ip="10.0.0.1", port=9000)
        d = peer.to_dict()
        assert d["name"] == "node"
        assert d["ip"] == "10.0.0.1"
        assert d["port"] == 9000

    def test_peer_has_encryption(self):
        from app.peer.peer_registry import PeerInfo
        peer_no_key = PeerInfo(name="n", ip="1.1.1.1", port=9000)
        assert peer_no_key.has_encryption() is False

        peer_with_key = PeerInfo(
            name="n", ip="1.1.1.1", port=9000,
            node_pubkey_hex=secrets.token_hex(32),
        )
        assert peer_with_key.has_encryption() is True

    def test_registry_update(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        is_new = reg.update("192.168.1.10", "node1", 9000)
        assert is_new is True
        is_new2 = reg.update("192.168.1.10", "node1", 9000)
        assert is_new2 is False

    def test_registry_active(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        reg.update("192.168.1.10", "node1", 9000)
        reg.update("192.168.1.11", "node2", 9000)
        active = reg.active()
        assert len(active) == 2

    def test_registry_get(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        reg.update("10.0.0.1", "n1", 9000)
        peer = reg.get("10.0.0.1")
        assert peer is not None
        assert peer.name == "n1"

    def test_registry_get_nonexistent(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        assert reg.get("99.99.99.99") is None

    def test_registry_cleanup(self):
        import time
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        reg.update("10.0.0.1", "old", 9000)
        # Manually make peer old
        reg._peers["10.0.0.1"].last_seen = time.monotonic() - 999
        reg.cleanup()
        assert len(reg.active()) == 0


class TestPeerEndpoints:
    """Peer REST endpoint tests."""

    def test_peers_list(self, client, logged_user):
        r = client.get("/api/peers", headers=logged_user["headers"])
        assert r.status_code == 200

    def test_peers_status(self, client):
        r = client.get("/api/peers/status")
        assert r.status_code == 200
        data = r.json()
        assert "ok" in data or "status" in data

    def test_peers_public_rooms(self, client):
        r = client.get("/api/peers/public-rooms")
        assert r.status_code == 200

    def test_peers_send_unauthenticated(self, client):
        r = client.post("/api/peers/send", json={
            "room_id": 1,
            "ciphertext": secrets.token_hex(32),
        })
        assert r.status_code in (401, 403, 422)


class TestFederationEndpoints:
    """Federation REST endpoint tests."""

    def test_federation_status(self, client):
        r = client.get("/api/federation/status")
        assert r.status_code in (200, 404)

    def test_federation_my_rooms(self, client, logged_user):
        r = client.get("/api/federation/my-rooms", headers=logged_user["headers"])
        assert r.status_code in (200, 404)

    def test_guest_login(self, client):
        r = client.post("/api/federation/guest-login", json={
            "display_name": f"Guest_{random_str(5)}",
            "x25519_pubkey": secrets.token_hex(32),
        })
        assert r.status_code in (200, 201, 400, 403, 422)


class TestPeerReceive:
    """Peer message receive endpoint."""

    def test_receive_encrypted_message(self, client):
        r = client.post("/api/peers/receive", json={
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(64),
            "sender_pubkey": secrets.token_hex(32),
        })
        assert r.status_code in (200, 400, 403, 422)

    def test_receive_plaintext_message(self, client):
        r = client.post("/api/peers/receive", json={
            "plaintext_payload": {
                "room_id": 1,
                "sender": "remote",
                "ciphertext": secrets.token_hex(32),
            },
            "sender_pubkey": secrets.token_hex(32),
        })
        assert r.status_code in (200, 400, 403, 422)
