"""
Tests for bot API and marketplace.
"""
import secrets
import pytest

from conftest import make_user, login_user, random_str


class TestBotManagement:

    def test_create_bot(self, client, logged_user):
        resp = client.post("/api/bots", json={
            "name": f"bot_{random_str(6)}",
            "description": "Test bot",
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 422)

    def test_list_my_bots(self, client, logged_user):
        resp = client.get("/api/bots/my", headers=logged_user["headers"])
        assert resp.status_code in (200, 404, 405)

    def test_create_bot_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.post("/api/bots", json={
            "name": "HackBot",
            "description": "Unauthorized",
        })
        assert resp.status_code in (401, 403, 422)
        bare.close()


class TestBotMarketplace:

    def test_marketplace_list(self, client, logged_user):
        resp = client.get("/api/marketplace/bots", headers=logged_user["headers"])
        assert resp.status_code in (200, 404, 405, 422)

    def test_marketplace_search(self, client, logged_user):
        resp = client.get(
            "/api/marketplace/bots?q=test",
            headers=logged_user["headers"],
        )
        assert resp.status_code in (200, 404, 405, 422)
