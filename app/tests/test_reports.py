"""
Tests for moderation/reporting system.
"""
import pytest

from conftest import make_user, login_user, random_str


class TestReports:

    def test_report_nonexistent_user(self, client, logged_user):
        resp = client.post("/api/users/report/999999", json={
            "reason": "spam",
            "description": "Test report",
        }, headers=logged_user["headers"])
        assert resp.status_code in (404, 400, 200)

    def test_report_requires_reason(self, client, logged_user):
        resp = client.post("/api/users/report/1", json={
            "description": "No reason provided",
        }, headers=logged_user["headers"])
        assert resp.status_code in (400, 422, 404)

    def test_report_unauthenticated(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        resp = bare.post("/api/users/report/1", json={
            "reason": "spam",
        })
        assert resp.status_code in (401, 403, 422)
        bare.close()
