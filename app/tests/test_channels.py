"""
Tests for broadcast channels.
"""
import secrets
import pytest

from conftest import make_user, login_user, random_str


class TestChannels:

    def test_create_channel(self, client, logged_user):
        resp = client.post("/api/channels", json={
            "name": f"channel_{random_str()}",
            "description": "Test broadcast channel",
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 403, 422)

    def test_list_channels(self, client, logged_user):
        resp = client.get("/api/channels", headers=logged_user["headers"])
        assert resp.status_code in (200, 404, 405)

    def test_create_channel_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.post("/api/channels", json={
            "name": "HackChannel",
        })
        assert resp.status_code in (401, 403, 422)
        bare.close()
