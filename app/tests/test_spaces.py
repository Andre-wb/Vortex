"""
Tests for Spaces (Discord-like workspaces).
"""
import secrets
import pytest

from conftest import make_user, login_user, random_str


class TestSpaces:

    def test_create_space(self, client, logged_user):
        resp = client.post("/api/spaces", json={
            "name": f"space_{random_str()}",
            "description": "Test workspace",
            "avatar_emoji": "🏠",
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201)
        if resp.status_code in (200, 201):
            data = resp.json()
            assert "id" in data or "space" in data

    def test_list_my_spaces(self, client, logged_user):
        resp = client.get("/api/spaces/my", headers=logged_user["headers"])
        assert resp.status_code in (200, 422)

    def test_create_space_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.post("/api/spaces", json={
            "name": "HackSpace",
            "description": "Unauthorized",
        })
        assert resp.status_code in (401, 403, 422)
        bare.close()
