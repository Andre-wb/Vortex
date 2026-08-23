"""Peer registry and federation tests."""

import secrets

from conftest import random_str


def _peer_view(**told):
    from app.peer.peer_registry import PeerInfo

    base = {
        "name": "node",
        "ip": "10.0.0.1",
        "port": 9000,
        "pubkey": None,
        "shortened_pubkey": None,
        "age_sec": 0.0,
        "online": True,
        "encrypted": False,
    }
    base.update(told)
    return PeerInfo.told(base)


class TestPeerRegistry:
    """Peer registry unit tests."""

    def test_peer_info_creation(self):
        peer = _peer_view(name="test-node", ip="192.168.1.100", port=9000, online=True)
        assert peer.name == "test-node"
        assert peer.ip == "192.168.1.100"
        assert peer.port == 9000
        assert peer.alive() is True

    def test_peer_info_to_dict(self):
        d = _peer_view(name="node", ip="10.0.0.1", port=9000).to_dict()
        assert d["name"] == "node"
        assert d["ip"] == "10.0.0.1"
        assert d["port"] == 9000

    def test_peer_has_encryption(self):
        assert _peer_view(encrypted=False).has_encryption() is False
        assert _peer_view(encrypted=True).has_encryption() is True

    def test_registry_update(self):
        from app.peer.peer_registry import PeerRegistry

        reg = PeerRegistry()
        assert reg.update("192.168.11.10", "node1", 9000) is True
        assert reg.update("192.168.11.10", "node1", 9000) is False

    def test_registry_active(self):
        from app.peer.peer_registry import PeerRegistry

        reg = PeerRegistry()
        reg.update("192.168.11.11", "node1", 9000)
        reg.update("192.168.11.12", "node2", 9000)
        named = [p.ip for p in reg.active()]
        assert "192.168.11.11" in named
        assert "192.168.11.12" in named

    def test_registry_get(self):
        from app.peer.peer_registry import PeerRegistry

        reg = PeerRegistry()
        reg.update("10.20.0.1", "n1", 9000)
        peer = reg.get("10.20.0.1")
        assert peer is not None
        assert peer.name == "n1"

    def test_registry_get_nonexistent(self):
        from app.peer.peer_registry import PeerRegistry

        reg = PeerRegistry()
        assert reg.get("99.99.99.99") is None

    def test_registry_cleanup(self):
        import time

        from app.config import Config
        from app.peer import peer_registry_backend as backend
        from app.peer.peer_registry import PeerRegistry

        reg = PeerRegistry()
        was = float(Config.PEER_TIMEOUT_SEC)
        backend.set_timeout(0.01)
        try:
            reg.update("10.20.0.2", "old", 9000)
            time.sleep(0.05)
            reg.cleanup()
            assert reg.get("10.20.0.2") is None
        finally:
            backend.set_timeout(was)


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

    def test_peers_public_rooms(self, client, logged_user):
        r = client.get("/api/peers/public-rooms", headers=logged_user["headers"])
        assert r.status_code == 200

    def test_peers_send_unauthenticated(self, client):
        r = client.post(
            "/api/peers/send",
            json={
                "room_id": 1,
                "ciphertext": secrets.token_hex(32),
            },
        )
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
        r = client.post(
            "/api/federation/guest-login",
            json={
                "display_name": f"Guest_{random_str(5)}",
                "x25519_pubkey": secrets.token_hex(32),
            },
        )
        assert r.status_code in (200, 201, 400, 403, 422)


class TestPeerReceive:
    """Peer message receive endpoint."""

    def test_receive_encrypted_message(self, client):
        r = client.post(
            "/api/peers/receive",
            json={
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(64),
                "sender_pubkey": secrets.token_hex(32),
            },
        )
        assert r.status_code in (200, 400, 403, 422)

    def test_receive_plaintext_message(self, client):
        r = client.post(
            "/api/peers/receive",
            json={
                "plaintext_payload": {
                    "room_id": 1,
                    "sender": "remote",
                    "ciphertext": secrets.token_hex(32),
                },
                "sender_pubkey": secrets.token_hex(32),
            },
        )
        assert r.status_code in (200, 400, 403, 422)
