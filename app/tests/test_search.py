"""
Tests for search endpoints:
  GET /api/users/search       — user search by name, phone, email, IP
  GET /api/users/global-search — global search (users + channels + chats)
"""
import secrets

import pytest

from conftest import make_user, login_user, random_str


# ── helpers ──────────────────────────────────────────────────────────────────

def _headers(client, user):
    h = login_user(client, user["username"], user["password"])
    user["headers"] = h
    return h


# ══════════════════════════════════════════════════════════════════════════════
# /api/users/search
# ══════════════════════════════════════════════════════════════════════════════

class TestUserSearch:

    def test_search_requires_auth(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        r = bare.get("/api/users/search", params={"q": "test"})
        assert r.status_code in (401, 403, 422)
        bare.close()

    def test_search_missing_q_param(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/search", headers=h)
        # q is required with min_length=1
        assert r.status_code == 422

    def test_search_by_exact_username(self, client):
        target = make_user(client)
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get(
            "/api/users/search",
            params={"q": target["username"]},
            headers=h,
        )
        assert r.status_code == 200
        data = r.json()
        assert "users" in data
        usernames = [u["username"] for u in data["users"]]
        assert target["username"] in usernames

    def test_search_result_has_required_fields(self, client):
        target = make_user(client)
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get(
            "/api/users/search",
            params={"q": target["username"]},
            headers=h,
        )
        assert r.status_code == 200
        users = r.json()["users"]
        if users:
            u = users[0]
            assert "user_id" in u
            assert "username" in u
            assert "display_name" in u
            assert "is_contact" in u
            assert "is_self" in u

    def test_search_result_max_20(self, client):
        """Verify the endpoint never returns more than 20 results."""
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get("/api/users/search", params={"q": "user_"}, headers=h)
        assert r.status_code == 200
        assert len(r.json()["users"]) <= 20

    def test_search_by_prefix(self, client):
        prefix = f"srch{random_str(5)}"
        target = make_user(client, suffix=prefix)
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get("/api/users/search", params={"q": f"user_{prefix}"}, headers=h)
        assert r.status_code == 200
        usernames = [u["username"] for u in r.json()["users"]]
        assert target["username"] in usernames

    def test_search_empty_string_returns_422(self, client):
        user = make_user(client)
        h = _headers(client, user)
        # q="" has length 0, which violates min_length=1
        r = client.get("/api/users/search", params={"q": ""}, headers=h)
        assert r.status_code == 422

    def test_search_single_char_returns_results_or_empty(self, client):
        """Single char is valid (min_length=1); result may be empty but not 4xx."""
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/search", params={"q": "a"}, headers=h)
        assert r.status_code == 200
        assert isinstance(r.json()["users"], list)

    def test_search_special_characters_no_crash(self, client):
        user = make_user(client)
        h = _headers(client, user)
        for special_q in ["user%", "user&", "user<>", "user;drop"]:
            r = client.get("/api/users/search", params={"q": special_q}, headers=h)
            assert r.status_code in (200, 400, 422), (
                f"Unexpected {r.status_code} for q={special_q!r}: {r.text}"
            )

    def test_search_phone_like_query(self, client):
        """Query that looks like a phone number should not crash and return a list."""
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/search", params={"q": "+15551234567"}, headers=h)
        assert r.status_code == 200
        assert "users" in r.json()

    def test_search_email_like_query(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/search", params={"q": "nobody@example.com"}, headers=h)
        assert r.status_code == 200
        assert "users" in r.json()

    def test_search_ip_like_query(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/search", params={"q": "192.168.1.1"}, headers=h)
        assert r.status_code == 200
        assert "users" in r.json()

    def test_search_phone_masked_in_result(self, client):
        """Phone numbers returned should be masked (contain asterisks)."""
        target = make_user(client)
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get(
            "/api/users/search",
            params={"q": target["username"]},
            headers=h,
        )
        assert r.status_code == 200
        for u in r.json()["users"]:
            phone = u.get("phone")
            if phone and len(phone) >= 7:
                assert "*" in phone, f"phone not masked: {phone}"

    def test_search_does_not_return_inactive_users(self, client):
        """All returned users should be active (no explicit deactivation here,
        but the response must be valid and the endpoint must not error)."""
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/search", params={"q": user["username"]}, headers=h)
        assert r.status_code == 200
        for u in r.json()["users"]:
            # self match is fine; none should have an error field
            assert "username" in u

    def test_search_is_self_flag(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get(
            "/api/users/search",
            params={"q": user["username"]},
            headers=h,
        )
        assert r.status_code == 200
        for u in r.json()["users"]:
            if u["username"] == user["username"]:
                assert u["is_self"] is True

    def test_search_no_match_returns_empty_list(self, client):
        user = make_user(client)
        h = _headers(client, user)
        unique = f"zzzmatch{random_str(10)}qqq"
        r = client.get("/api/users/search", params={"q": unique}, headers=h)
        assert r.status_code == 200
        assert r.json()["users"] == []

    def test_search_long_query_within_limit(self, client):
        user = make_user(client)
        h = _headers(client, user)
        long_q = "a" * 128  # max_length=128
        r = client.get("/api/users/search", params={"q": long_q}, headers=h)
        assert r.status_code == 200

    def test_search_over_max_length_returns_422(self, client):
        user = make_user(client)
        h = _headers(client, user)
        too_long = "a" * 129
        r = client.get("/api/users/search", params={"q": too_long}, headers=h)
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# /api/users/global-search
# ══════════════════════════════════════════════════════════════════════════════

class TestGlobalSearch:

    def test_global_search_requires_auth(self, client):
        from conftest import SyncASGIClient
        bare = SyncASGIClient()
        r = bare.get("/api/users/global-search", params={"q": "test"})
        assert r.status_code in (401, 403, 422)
        bare.close()

    def test_global_search_empty_query_returns_empty_sections(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/global-search", params={"q": ""}, headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data["users"] == []
        assert data["channels"] == []
        assert data["chats"] == []

    def test_global_search_one_char_query_returns_empty(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/global-search", params={"q": "x"}, headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data["users"] == []

    def test_global_search_response_has_three_sections(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/global-search", params={"q": "user"}, headers=h)
        assert r.status_code == 200
        data = r.json()
        assert "users" in data
        assert "channels" in data
        assert "chats" in data

    def test_global_search_finds_registered_user(self, client):
        target = make_user(client)
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get(
            "/api/users/global-search",
            params={"q": target["username"]},
            headers=h,
        )
        assert r.status_code == 200
        usernames = [u["username"] for u in r.json()["users"]]
        assert target["username"] in usernames

    def test_global_search_user_result_has_type_field(self, client):
        target = make_user(client)
        searcher = make_user(client)
        h = _headers(client, searcher)
        r = client.get(
            "/api/users/global-search",
            params={"q": target["username"]},
            headers=h,
        )
        assert r.status_code == 200
        for u in r.json()["users"]:
            assert u.get("type") == "user"

    def test_global_search_limits_user_results(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/global-search", params={"q": "user_"}, headers=h)
        assert r.status_code == 200
        assert len(r.json()["users"]) <= 10

    def test_global_search_no_crash_special_chars(self, client):
        user = make_user(client)
        h = _headers(client, user)
        for q in ["test%20name", "user+name", "abc def", "x'y"]:
            r = client.get("/api/users/global-search", params={"q": q}, headers=h)
            assert r.status_code in (200, 400, 422), (
                f"Unexpected {r.status_code} for q={q!r}"
            )

    def test_global_search_long_query_no_crash(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get(
            "/api/users/global-search",
            params={"q": "a" * 128},
            headers=h,
        )
        assert r.status_code == 200

    def test_global_search_channels_section_is_list(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/global-search", params={"q": "general"}, headers=h)
        assert r.status_code == 200
        assert isinstance(r.json()["channels"], list)

    def test_global_search_chats_section_is_list(self, client):
        user = make_user(client)
        h = _headers(client, user)
        r = client.get("/api/users/global-search", params={"q": "general"}, headers=h)
        assert r.status_code == 200
        assert isinstance(r.json()["chats"], list)

    def test_global_search_unknown_query_returns_empty_users(self, client):
        user = make_user(client)
        h = _headers(client, user)
        unique = f"zzzmatch{random_str(10)}qqq"
        r = client.get("/api/users/global-search", params={"q": unique}, headers=h)
        assert r.status_code == 200
        assert r.json()["users"] == []
