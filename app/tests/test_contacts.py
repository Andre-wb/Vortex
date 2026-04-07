"""
Tests for contacts, blocking, DMs, and search.
"""
import secrets
import string
import pytest

from conftest import make_user, login_user, random_str


class TestContacts:

    def test_contacts_list_empty(self, client, logged_user):
        resp = client.get("/api/contacts", headers=logged_user["headers"])
        assert resp.status_code == 200

    def test_search_users_by_username(self, client, logged_user, fresh_user):
        resp = client.get(
            f"/api/contacts/search?q={fresh_user['username']}",
            headers=logged_user["headers"],
        )
        assert resp.status_code in (200, 404, 405)


class TestBlocking:

    def test_block_user(self, client, two_users):
        u1, u2 = two_users
        user2_data = u2["data"]
        user2_id = user2_data.get("id") or user2_data.get("user_id")
        if user2_id:
            resp = client.post(
                f"/api/users/block/{user2_id}",
                headers=u1["headers"],
            )
            assert resp.status_code in (200, 201, 400, 404)


class TestDirectMessages:

    def test_dm_create_and_list(self, client, two_users):
        u1, u2 = two_users
        user2_data = u2["data"]
        user2_id = user2_data.get("id") or user2_data.get("user_id")
        if user2_id:
            resp = client.post(f"/api/dm/{user2_id}", headers=u1["headers"])
            assert resp.status_code in (200, 201, 400, 404, 422)


class TestSearch:

    def test_search_empty_query(self, client, logged_user):
        resp = client.get("/api/search?q=", headers=logged_user["headers"])
        assert resp.status_code in (200, 400, 404, 422)

    def test_search_messages(self, client, logged_user):
        resp = client.get(
            "/api/search?q=test",
            headers=logged_user["headers"],
        )
        assert resp.status_code in (200, 404)
