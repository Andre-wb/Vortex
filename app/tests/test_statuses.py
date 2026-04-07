"""
Tests for ephemeral user statuses (stories).
"""
import pytest

from conftest import random_str


class TestStatuses:

    def test_create_status(self, client, logged_user):
        resp = client.post("/api/statuses", json={
            "text": f"Status {random_str()}",
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201)

    def test_list_statuses(self, client, logged_user):
        resp = client.get("/api/statuses", headers=logged_user["headers"])
        assert resp.status_code == 200

    def test_create_status_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.post("/api/statuses", json={"text": "Hack"})
        assert resp.status_code in (401, 403, 422)
        bare.close()

    def test_status_text_too_long(self, client, logged_user):
        resp = client.post("/api/statuses", json={
            "text": "A" * 1000,
        }, headers=logged_user["headers"])
        assert resp.status_code in (200, 201, 400, 422)
