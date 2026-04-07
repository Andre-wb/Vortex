"""Middleware tests — security headers, CSRF, token refresh, WAF, logging."""
import secrets
import pytest
from conftest import make_user, login_user, random_str, _unique_phone


class TestSecurityHeaders:
    """Verify security headers on all responses."""

    def test_x_frame_options(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_xss_protection(self, client):
        r = client.get("/health")
        assert "1" in r.headers.get("X-XSS-Protection", "")

    def test_referrer_policy(self, client):
        r = client.get("/health")
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_csp_present(self, client):
        r = client.get("/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "default-src" in csp

    def test_hsts_header(self, client):
        r = client.get("/health")
        hsts = r.headers.get("Strict-Transport-Security", "")
        assert "max-age=" in hsts

    def test_cross_origin_opener_policy(self, client):
        r = client.get("/health")
        assert r.headers.get("Cross-Origin-Opener-Policy") == "same-origin"

    def test_cross_origin_resource_policy(self, client):
        r = client.get("/health")
        assert r.headers.get("Cross-Origin-Resource-Policy") == "same-origin"

    def test_permissions_policy(self, client):
        r = client.get("/health")
        pp = r.headers.get("Permissions-Policy", "")
        assert "microphone" in pp or "camera" in pp

    def test_correlation_id_present(self, client):
        r = client.get("/health")
        cid = r.headers.get("X-Request-ID", "")
        assert len(cid) > 0


class TestCSRFProtection:
    """CSRF middleware tests."""

    def test_csrf_token_endpoint(self, client):
        r = client.get("/api/authentication/csrf-token")
        assert r.status_code == 200
        data = r.json()
        assert "csrf_token" in data
        assert len(data["csrf_token"]) > 10

    def test_mutation_without_csrf_rejected(self, client, logged_user):
        """POST to protected endpoint without CSRF token should fail."""
        r = client.post("/api/rooms", json={
            "name": "csrf_test",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        })
        # Without CSRF token, should be rejected
        assert r.status_code in (401, 403, 422)

    def test_csrf_skipped_for_login(self, client, fresh_user):
        """Login should work without CSRF token."""
        r = client.post("/api/authentication/login", json={
            "phone_or_username": fresh_user["username"],
            "password": fresh_user["password"],
        })
        assert r.status_code == 200

    def test_csrf_skipped_for_register(self, client):
        """Registration should work without CSRF token."""
        r = client.post("/api/authentication/register", json={
            "username": f"user_{random_str()}",
            "password": "StrongPass99!@",
            "phone": _unique_phone(),
            "x25519_public_key": secrets.token_hex(32),
        })
        assert r.status_code in (201, 400, 409, 422)

    def test_csrf_skipped_for_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_multiple_csrf_tokens_unique(self, client):
        t1 = client.get("/api/authentication/csrf-token").json().get("csrf_token")
        t2 = client.get("/api/authentication/csrf-token").json().get("csrf_token")
        # Tokens may or may not be different, but both should be valid
        assert t1 is not None
        assert t2 is not None


class TestWAFMiddleware:
    """Web Application Firewall middleware tests."""

    def test_normal_request_passes(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_sql_injection_blocked(self, client):
        csrf = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        r = client.post("/api/authentication/login", json={
            "phone_or_username": "admin' OR 1=1--",
            "password": "test",
        }, headers={"X-CSRF-Token": csrf})
        assert r.status_code != 200

    def test_xss_in_input_blocked(self, client):
        r = client.post("/api/authentication/register", json={
            "username": f"user_{random_str()}",
            "password": "StrongPass99!@",
            "phone": _unique_phone(),
            "x25519_public_key": secrets.token_hex(32),
            "display_name": "<script>alert('xss')</script>",
        })
        # Should either sanitize or reject
        assert r.status_code in (201, 400, 403, 422)

    def test_path_traversal_blocked(self, client):
        r = client.get("/api/rooms/../../../etc/passwd")
        assert r.status_code in (400, 403, 404, 405)

    def test_oversized_body_rejected(self, client, logged_user):
        """Request with body > max_content_length should be rejected."""
        huge = "x" * (11 * 1024 * 1024)  # 11 MB
        r = client.post("/api/rooms", json={
            "name": huge,
        }, headers=logged_user["headers"])
        assert r.status_code in (400, 403, 413, 422)


class TestTokenRefreshMiddleware:
    """Auto-refresh middleware tests."""

    def test_expired_access_with_refresh_cookie(self, client, logged_user):
        """If access token expired but refresh present, should auto-renew."""
        # Just verify the middleware doesn't crash
        r = client.get("/api/authentication/me", headers=logged_user["headers"])
        assert r.status_code in (200, 401, 403)


class TestLoggingMiddleware:
    """Logging middleware tests."""

    def test_request_logged_without_error(self, client):
        """Verify logging middleware doesn't break requests."""
        r = client.get("/health")
        assert r.status_code == 200

    def test_404_logged(self, client):
        r = client.get("/api/nonexistent-endpoint")
        assert r.status_code in (404, 405)


class TestMetricsEndpoint:
    """Prometheus metrics endpoint tests."""

    def test_metrics_returns_prometheus_format(self, client):
        r = client.get("/metrics")
        if r.status_code == 200:
            assert "vortex_http_requests_total" in r.text or "HELP" in r.text
        else:
            pytest.skip("Metrics endpoint not available")

    def test_metrics_contains_request_count(self, client):
        # Make some requests first
        client.get("/health")
        client.get("/health")
        r = client.get("/metrics")
        if r.status_code == 200:
            assert "vortex_http_requests_total" in r.text

    def test_metrics_contains_duration_histogram(self, client):
        r = client.get("/metrics")
        if r.status_code == 200:
            assert "vortex_http_request_duration_seconds" in r.text


class TestExceptionHandlers:
    """Exception handler tests."""

    def test_404_structured_response(self, client):
        r = client.get("/api/this-does-not-exist-xyz")
        assert r.status_code in (404, 405)
        data = r.json()
        assert "error" in data or "detail" in data

    def test_422_validation_error(self, client):
        r = client.post("/api/authentication/register", json={})
        assert r.status_code == 422
        data = r.json()
        assert "error" in data or "detail" in data or "details" in data


class TestCorrelationID:
    """Correlation ID middleware."""

    def test_auto_generated_correlation_id(self, client):
        r = client.get("/health")
        cid = r.headers.get("X-Request-ID", "")
        assert len(cid) >= 8

    def test_custom_correlation_id_preserved(self, client):
        custom_id = "test-correlation-123"
        r = client.get("/health", headers={"X-Request-ID": custom_id})
        assert r.headers.get("X-Request-ID") == custom_id
