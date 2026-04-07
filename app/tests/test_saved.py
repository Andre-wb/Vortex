"""
Tests for saved messages.
"""
import pytest


class TestSavedMessages:

    def test_list_saved_empty(self, client, logged_user):
        resp = client.get("/api/saved", headers=logged_user["headers"])
        assert resp.status_code == 200

    def test_save_nonexistent_message(self, client, logged_user):
        resp = client.post("/api/saved/999999", headers=logged_user["headers"])
        assert resp.status_code in (404, 400, 200)

    def test_saved_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.get("/api/saved")
        assert resp.status_code in (401, 403)
        bare.close()
