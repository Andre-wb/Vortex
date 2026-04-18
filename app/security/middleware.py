"""
Middleware стек.

Порядок подключения (в main.py):
  1. SecurityHeadersMiddleware  — безопасные заголовки
  2. LoggingMiddleware          — логирование запросов
  3. CSRFMiddleware             — защита от CSRF
  4. TokenRefreshMiddleware     — автообновление JWT

WAF подключается отдельно как ASGI middleware.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.database import SessionLocal
from app.security.auth_jwt import verify_refresh_token, create_access_token

logger = logging.getLogger(__name__)
_IS_PROD = os.getenv("ENVIRONMENT", "development") == "production"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Устанавливает заголовки безопасности. CSP настроен для WebRTC и WebSocket."""

    async def dispatch(self, request: Request, call_next):
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            return response

        response.headers["X-Frame-Options"]              = "DENY"
        response.headers["X-Content-Type-Options"]       = "nosniff"
        response.headers["X-XSS-Protection"]             = "1; mode=block"
        response.headers["Referrer-Policy"]              = "strict-origin-when-cross-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self' wss: ws: https:; "
            "media-src 'self' blob:; "
            "worker-src 'self' blob:; "
            "frame-src 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        response.headers["Permissions-Policy"] = (
            "geolocation=(), payment=(), usb=(), "
            "microphone=(self), camera=(self)"
        )

        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Логирует все HTTP запросы с временем обработки."""

    async def dispatch(self, request: Request, call_next):
        if (request.url.path.startswith("/static/")
                or request.headers.get("upgrade", "").lower() == "websocket"):
            return await call_next(request)

        from app.security.ip_privacy import raw_ip_for_ratelimit
        start = time.perf_counter()
        ip = raw_ip_for_ratelimit(request)

        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Unhandled: {request.method} {request.url.path} — {e}", exc_info=True)
            return PlainTextResponse("Internal Server Error", status_code=500)

        elapsed = (time.perf_counter() - start) * 1000
        # Sanitize BMP paths to prevent metadata leakage in logs
        _path = request.url.path
        if _path.startswith("/api/bmp/"):
            _path = "/api/bmp/***"
        elif _path.startswith("/ws/") and not _path.startswith("/ws/notifications"):
            _path = "/ws/***"
        logger.info(
            f"{request.method:6s} {_path:<40s} "
            f"{response.status_code} {elapsed:6.1f}ms  {ip}"
        )
        return response


class CSRFMiddleware(BaseHTTPMiddleware):

    _SAFE_METHODS  = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
    _SKIP_PATHS    = frozenset({
        "/api/files/upload-chunk/",
        "/api/files/upload-init",
        "/api/files/upload-complete/",
        "/health", "/favicon.ico", "/robots.txt",
        "/api/authentication/login", "/api/authentication/register",
        "/api/authentication/refresh",
        "/api/authentication/security-questions/load",
        "/api/authentication/security-questions/recover",
        "/api/authentication/security-questions/setup",
        "/api/authentication/verify-password",
        "/api/authentication/change-password",
        "/api/authentication/profile", "/api/authentication/avatar",
        "/api/peers/receive",
        "/api/peers/status",
        "/api/peers/federated-join",
        "/api/federation/guest-login",
        "/api/docs",
    })
    _SKIP_PREFIXES = (
        "/static/", "/waf/", "/api/rooms/join/",
        "/api/push/",
        "/api/authentication/qr-",
        "/api/authentication/passkey/",
        "/api/files/upload-chunk/",
        "/api/files/upload-complete/",
        "/api/files/upload-cancel/",
        "/api/files/upload-status/",
        "/api/files/upload-init",
        "/api/stream/",
        "/api/users/block/",
        "/api/users/report/",
        "/api/dm/store-key/",
        "/api/saved/",
        "/api/stickers/",
        "/api/bot/",   # Bot API endpoints use token auth, not CSRF
        "/api/bots/",  # Bot management endpoints
        "/api/marketplace/",  # Marketplace endpoints (JWT auth)
        "/api/spaces/",       # Spaces endpoints (JWT auth)
        "/api/global/",       # P2P inter-node endpoints (no user session)
        "/api/transport/",    # Transport layer endpoints (JWT auth)
        "/api/ai/",           # AI assistant endpoints (JWT auth)
        "/api/privacy/",      # Privacy settings (JWT auth)
        "/api/authentication/account-ttl",  # Account TTL setting
        "/api/authentication/session-limit", # Session limit setting
        "/api/translate",     # Translation endpoint
        "/api/bmp/",          # Blind Mailbox Protocol (anonymous by design)
        "/cover/",            # Cover traffic pages (public)
    )

    async def dispatch(self, request: Request, call_next):
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        path = request.url.path
        if (path in self._SKIP_PATHS
                or any(path.startswith(p) for p in self._SKIP_PREFIXES)
                or (path.startswith("/api/rooms/") and path.endswith("/read"))
                or (path.startswith("/api/rooms/") and path.endswith("/mute"))
                or (path.startswith("/api/rooms/") and path.endswith("/pin"))
                or (path.startswith("/api/rooms/") and path.endswith("/auto-delete"))
                or (path.startswith("/api/rooms/") and path.endswith("/slow-mode"))
                or (path.startswith("/api/rooms/") and path.endswith("/avatar"))
                or (path.startswith("/api/rooms/") and "/tasks" in path)):
            response = await call_next(request)
            self._set_csrf_cookie(response, request)
            return response

        csrf_cookie = request.cookies.get("csrf_token")
        if not csrf_cookie:
            csrf_cookie = secrets.token_urlsafe(32)

        request.state.csrf_token = csrf_cookie

        if request.method in self._SAFE_METHODS:
            response = await call_next(request)
            self._set_csrf_cookie(response, request, csrf_cookie)
            return response

        content_type = request.headers.get("content-type", "")
        submitted    = None

        try:
            if "application/json" in content_type:
                submitted = request.headers.get("x-csrf-token")
                if not submitted:
                    body_bytes = await request.body()
                    if body_bytes:
                        try:
                            body = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                            submitted = body.get("csrf_token")
                        except (json.JSONDecodeError, AttributeError):
                            pass
                    if not hasattr(request, "_body"):
                        request._body = body_bytes if body_bytes else b""

            elif "multipart/form-data" in content_type:
                submitted = request.headers.get("x-csrf-token")

            elif "application/x-www-form-urlencoded" in content_type:
                form = await request.form()
                for field_name in ("csrf_token", "_csrf", "csrf-token"):
                    if field_name in form:
                        submitted = form[field_name]
                        break
                if not submitted:
                    submitted = request.headers.get("x-csrf-token")
                request.state.form = form

            else:
                submitted = request.headers.get("x-csrf-token")

        except Exception as e:
            logger.error(f"CSRF read error: {e}", exc_info=True)
            return JSONResponse({"error": "CSRF verification error"}, status_code=500)

        if not submitted:
            logger.warning(f"CSRF: нет токена для {request.method} {path}")
            return JSONResponse(
                {"error": "CSRF token not provided",
                 "hint": "Add X-CSRF-Token header or csrf_token field"},
                status_code=403, headers={"X-CSRF-Required": "true"}
            )

        if not secrets.compare_digest(str(submitted), str(csrf_cookie)):
            logger.warning(f"CSRF: неверный токен для {path}")
            return JSONResponse(
                {"error": "Invalid CSRF token"},
                status_code=403, headers={"X-CSRF-Required": "true"}
            )

        response = await call_next(request)
        if response is None:
            return PlainTextResponse("Internal Server Error", status_code=500)
        self._set_csrf_cookie(response, request, csrf_cookie)
        return response

    @staticmethod
    def _set_csrf_cookie(response, request: Request, token: Optional[str] = None):
        if not request.cookies.get("csrf_token"):
            token = token or secrets.token_urlsafe(32)
            response.set_cookie(
                "csrf_token", token,
                httponly=False,
                secure=_IS_PROD,
                samesite="Strict",
                max_age=86400, path="/",
            )


class TokenRefreshMiddleware(BaseHTTPMiddleware):
    """Автоматически обновляет access_token если он отсутствует, но есть refresh_token."""

    _SKIP = frozenset({
        "/api/authentication/login", "/api/authentication/register",
        "/api/authentication/refresh",
        "/api/authentication/logout", "/health", "/favicon.ico",
    })

    async def dispatch(self, request: Request, call_next):
        if (request.url.path.startswith("/static/")
                or request.url.path in self._SKIP
                or request.headers.get("upgrade", "").lower() == "websocket"):
            return await call_next(request)

        if not request.cookies.get("access_token") and request.cookies.get("refresh_token"):
            try:
                db = SessionLocal()
                try:
                    raw = request.cookies["refresh_token"]
                    user = verify_refresh_token(raw, db)
                    new_access = create_access_token(user.id, user.phone, user.username)
                    # Создаём новый refresh token (ротация)
                    from app.security.auth_jwt import create_refresh_token
                    new_refresh, _ = create_refresh_token(user.id, db)
                    response = await call_next(request)
                    response.set_cookie(
                        "access_token", new_access,
                        httponly=True, secure=_IS_PROD,
                        samesite="Lax", max_age=3600, path="/",
                    )
                    response.set_cookie(
                        "refresh_token", new_refresh,
                        httponly=True, secure=_IS_PROD,
                        samesite="Lax", max_age=86400 * 30, path="/",
                    )
                    return response
                finally:
                    db.close()
            except Exception as e:
                logger.debug(f"Token refresh failed: {e}")

        return await call_next(request)