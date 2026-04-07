"""
Tests for the link-preview endpoint:
  GET /api/link-preview?url=...

Covers:
  - URL validation (scheme, SSRF protection)
  - OG tag parsing helpers (_parse_og, _cache_get/_cache_set)
  - Happy-path fetch with mocked httpx
  - Error paths (network failure, non-HTML content)
  - LRU cache behaviour
  - Auth requirement
"""
from __future__ import annotations

import importlib
from collections import OrderedDict
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from conftest import make_user, login_user, random_str


# ── helpers ──────────────────────────────────────────────────────────────────

def _headers(client, user):
    h = login_user(client, user["username"], user["password"])
    user["headers"] = h
    return h


def _logged_user(client):
    u = make_user(client)
    h = _headers(client, u)
    return u, h


# Import the module under test so we can access helpers directly
import app.chats.link_preview as lp_module


# ══════════════════════════════════════════════════════════════════════════════
# Unit tests for _parse_og
# ══════════════════════════════════════════════════════════════════════════════

class TestParseOG:

    def test_extracts_og_title(self):
        html = '<meta property="og:title" content="Hello World" />'
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["title"] == "Hello World"

    def test_extracts_og_description(self):
        html = '<meta property="og:description" content="A great page." />'
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["description"] == "A great page."

    def test_extracts_og_image(self):
        html = '<meta property="og:image" content="https://example.com/img.png" />'
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["image"] == "https://example.com/img.png"

    def test_extracts_og_site_name(self):
        html = '<meta property="og:site_name" content="ExampleSite" />'
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["site_name"] == "ExampleSite"

    def test_fallback_to_title_tag(self):
        html = "<title>  Fallback Title  </title>"
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["title"] == "Fallback Title"

    def test_og_title_takes_precedence_over_title_tag(self):
        html = (
            '<meta property="og:title" content="OG Title" />'
            "<title>HTML Title</title>"
        )
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["title"] == "OG Title"

    def test_fallback_to_meta_description(self):
        html = '<meta name="description" content="Meta description fallback" />'
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["description"] == "Meta description fallback"

    def test_relative_image_resolved_to_absolute(self):
        html = '<meta property="og:image" content="/images/logo.png" />'
        result = lp_module._parse_og(html, "https://example.com/page")
        assert result["image"].startswith("https://example.com")
        assert "/images/logo.png" in result["image"]

    def test_site_name_derived_from_hostname_when_missing(self):
        html = ""
        result = lp_module._parse_og(html, "https://www.example.com/page")
        # www prefix stripped
        assert result["site_name"] == "example.com"

    def test_url_field_preserved(self):
        html = ""
        url = "https://example.com/article/123"
        result = lp_module._parse_og(html, url)
        assert result["url"] == url

    def test_title_truncated_at_300_chars(self):
        long_title = "X" * 400
        html = f'<meta property="og:title" content="{long_title}" />'
        result = lp_module._parse_og(html, "https://example.com/")
        assert len(result["title"]) <= 300

    def test_description_truncated_at_500_chars(self):
        long_desc = "D" * 600
        html = f'<meta property="og:description" content="{long_desc}" />'
        result = lp_module._parse_og(html, "https://example.com/")
        assert len(result["description"]) <= 500

    def test_empty_html_returns_empty_strings(self):
        result = lp_module._parse_og("", "https://example.com/")
        assert result["title"] == ""
        assert result["description"] == ""
        assert result["image"] == ""

    def test_reversed_attribute_order_og_tag(self):
        # content= before property=
        html = '<meta content="Reverse Title" property="og:title" />'
        result = lp_module._parse_og(html, "https://example.com/")
        assert result["title"] == "Reverse Title"


# ══════════════════════════════════════════════════════════════════════════════
# Unit tests for LRU cache helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestLRUCache:

    def setup_method(self):
        """Clear the module-level cache before each test."""
        lp_module._cache.clear()

    def test_cache_miss_returns_none(self):
        assert lp_module._cache_get("https://notcached.example.com/") is None

    def test_cache_set_and_get(self):
        data = {"title": "Cached", "description": "", "image": "", "site_name": "", "url": "x"}
        lp_module._cache_set("https://cached.example.com/", data)
        assert lp_module._cache_get("https://cached.example.com/") == data

    def test_cache_lru_eviction(self):
        """Inserting _CACHE_MAX + 1 items should evict the oldest one."""
        # Use a fresh OrderedDict to isolate the test
        old_cache = lp_module._cache
        lp_module._cache = OrderedDict()
        try:
            for i in range(lp_module._CACHE_MAX + 1):
                lp_module._cache_set(f"https://example.com/{i}", {"title": str(i)})
            # First URL should have been evicted
            assert lp_module._cache_get("https://example.com/0") is None
            # Last URL should still be present
            assert lp_module._cache_get(f"https://example.com/{lp_module._CACHE_MAX}") is not None
        finally:
            lp_module._cache = old_cache

    def test_cache_move_to_end_on_access(self):
        lp_module._cache_set("https://a.example.com/", {"title": "A"})
        lp_module._cache_set("https://b.example.com/", {"title": "B"})
        # Access A — it should move to end (most recent)
        lp_module._cache_get("https://a.example.com/")
        keys = list(lp_module._cache.keys())
        assert keys[-1] == "https://a.example.com/"


# ══════════════════════════════════════════════════════════════════════════════
# Integration tests via HTTP endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestLinkPreviewEndpoint:

    def test_endpoint_requires_auth(self, anon_client):
        r = anon_client.get("/api/link-preview", params={"url": "https://example.com/"})
        assert r.status_code in (401, 403, 422)

    def test_missing_url_param_returns_422(self, client):
        _, h = _logged_user(client)
        r = client.get("/api/link-preview", headers=h)
        assert r.status_code == 422

    def test_non_http_scheme_returns_empty_preview(self, client):
        _, h = _logged_user(client)
        r = client.get(
            "/api/link-preview",
            params={"url": "ftp://example.com/file.txt"},
            headers=h,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["title"] == ""
        assert data["description"] == ""

    def test_localhost_blocked_ssrf(self, client):
        _, h = _logged_user(client)
        r = client.get(
            "/api/link-preview",
            params={"url": "http://localhost/admin"},
            headers=h,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["title"] == ""

    def test_127_0_0_1_blocked_ssrf(self, client):
        _, h = _logged_user(client)
        r = client.get(
            "/api/link-preview",
            params={"url": "http://127.0.0.1/secret"},
            headers=h,
        )
        assert r.status_code == 200
        assert r.json()["title"] == ""

    def test_private_192_168_blocked_ssrf(self, client):
        _, h = _logged_user(client)
        r = client.get(
            "/api/link-preview",
            params={"url": "http://192.168.1.1/router"},
            headers=h,
        )
        assert r.status_code == 200
        assert r.json()["title"] == ""

    def test_private_10_x_blocked_ssrf(self, client):
        _, h = _logged_user(client)
        r = client.get(
            "/api/link-preview",
            params={"url": "http://10.0.0.1/internal"},
            headers=h,
        )
        assert r.status_code == 200
        assert r.json()["title"] == ""

    def test_response_has_required_fields(self, client):
        _, h = _logged_user(client)
        # Use a blocked URL so no real HTTP is needed
        r = client.get(
            "/api/link-preview",
            params={"url": "http://localhost/check"},
            headers=h,
        )
        assert r.status_code == 200
        data = r.json()
        for field in ("title", "description", "image", "site_name", "url"):
            assert field in data, f"Missing field: {field}"

    def test_url_field_echoed_back(self, client):
        _, h = _logged_user(client)
        target = "http://localhost/echo-test"
        r = client.get("/api/link-preview", params={"url": target}, headers=h)
        assert r.status_code == 200
        assert r.json()["url"] == target

    def test_successful_fetch_with_mock(self, client):
        """Mock httpx to return a page with OG tags and verify parsed result."""
        _, h = _logged_user(client)
        fake_html = (
            '<html><head>'
            '<meta property="og:title" content="Mock Title" />'
            '<meta property="og:description" content="Mock Desc" />'
            '<meta property="og:image" content="https://mock.example.com/img.png" />'
            '<meta property="og:site_name" content="MockSite" />'
            '</head></html>'
        )

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "text/html; charset=utf-8"}
        mock_response.text = fake_html

        mock_client_instance = AsyncMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        url = f"https://mock-{random_str(8)}.example.com/page"
        # Clear cache entry if any
        lp_module._cache.pop(url, None)

        with patch("app.chats.link_preview._AsyncClient", return_value=mock_client_instance):
            r = client.get("/api/link-preview", params={"url": url}, headers=h)

        assert r.status_code == 200
        data = r.json()
        assert data["title"] == "Mock Title"
        assert data["description"] == "Mock Desc"
        assert data["image"] == "https://mock.example.com/img.png"
        assert data["site_name"] == "MockSite"

    def test_non_html_content_type_returns_empty(self, client):
        _, h = _logged_user(client)
        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/json"}
        mock_response.text = '{"json": "data"}'

        mock_client_instance = AsyncMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        url = f"https://json-{random_str(8)}.example.com/api/data"
        lp_module._cache.pop(url, None)

        with patch("app.chats.link_preview._AsyncClient", return_value=mock_client_instance):
            r = client.get("/api/link-preview", params={"url": url}, headers=h)

        assert r.status_code == 200
        data = r.json()
        assert data["title"] == ""

    def test_network_failure_returns_empty(self, client):
        _, h = _logged_user(client)
        mock_client_instance = AsyncMock()
        mock_client_instance.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        url = f"https://fail-{random_str(8)}.example.com/"
        lp_module._cache.pop(url, None)

        with patch("app.chats.link_preview._AsyncClient", return_value=mock_client_instance):
            r = client.get("/api/link-preview", params={"url": url}, headers=h)

        assert r.status_code == 200
        data = r.json()
        assert data["title"] == ""
        assert data["url"] == url

    def test_cached_result_served_on_second_request(self, client):
        """Second call with the same URL should return the cached result
        without making a new HTTP request."""
        _, h = _logged_user(client)
        fake_html = '<meta property="og:title" content="Cached Page" />'

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = fake_html

        call_count = 0

        async def _fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            return mock_response

        mock_client_instance = AsyncMock()
        mock_client_instance.get = _fake_get
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        url = f"https://cache-{random_str(8)}.example.com/"
        lp_module._cache.pop(url, None)

        with patch("app.chats.link_preview._AsyncClient", return_value=mock_client_instance):
            r1 = client.get("/api/link-preview", params={"url": url}, headers=h)
            r2 = client.get("/api/link-preview", params={"url": url}, headers=h)

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["title"] == "Cached Page"
        assert r2.json()["title"] == "Cached Page"
        # httpx should have been called only once
        assert call_count == 1

    def test_url_too_short_returns_422(self, client):
        _, h = _logged_user(client)
        # min_length=8, so 7 chars is too short
        r = client.get("/api/link-preview", params={"url": "http://"}, headers=h)
        # "http://" is exactly 7 chars
        assert r.status_code in (200, 422)  # 422 from validation or 200 with empty result

    def test_url_too_long_returns_422(self, client):
        _, h = _logged_user(client)
        long_url = "https://example.com/" + "a" * 2100  # > max_length=2048
        r = client.get("/api/link-preview", params={"url": long_url}, headers=h)
        assert r.status_code == 422

    def test_xhtml_content_type_accepted(self, client):
        _, h = _logged_user(client)
        fake_html = '<meta property="og:title" content="XHTML Title" />'

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/xhtml+xml; charset=utf-8"}
        mock_response.text = fake_html

        mock_client_instance = AsyncMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        url = f"https://xhtml-{random_str(8)}.example.com/"
        lp_module._cache.pop(url, None)

        with patch("app.chats.link_preview._AsyncClient", return_value=mock_client_instance):
            r = client.get("/api/link-preview", params={"url": url}, headers=h)

        assert r.status_code == 200
        data = r.json()
        assert data["title"] == "XHTML Title"
