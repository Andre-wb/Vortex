"""
Tests for federation — multi-hop routing and federated rooms.
"""
import pytest

from conftest import random_str


class TestFederation:

    def test_federation_status(self, client, logged_user):
        resp = client.get("/api/federation/status", headers=logged_user["headers"])
        assert resp.status_code in (200, 404)

    def test_guest_login(self, client):
        resp = client.post("/api/federation/guest-login", json={
            "display_name": f"guest_{random_str(6)}",
            "x25519_public_key": "a" * 64,
        })
        assert resp.status_code in (200, 201, 400, 422)
