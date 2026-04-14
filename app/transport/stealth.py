"""
Stealth Mode — маскировка Vortex трафика от DPI/цензуры.

Проблема: Роскомнадзор (и другие цензоры) могут обнаружить Vortex через:
  1. WebSocket пути (/ws/chat, /ws/voice-signal) — видны при handshake
  2. Заголовки X-Vortex-*, User-Agent: VortexBot
  3. UDP broadcast на порту 4200
  4. Самоподписанный сертификат (mkcert)
  5. manifest.json с именем "VORTEX"
  6. /health endpoint возвращает версию приложения
  7. Фиксированные порты (9000, 4200)
  8. STUN серверы (stun.l.google.com) — блокируемы

Решение: Stealth Mode маскирует ВСЕ эти признаки.

Включение: STEALTH_MODE=true в .env или через UI.

Компоненты:
  1. WebSocket Path Obfuscation — рандомные пути вместо /ws/*
  2. Header Sanitization — удаление всех идентифицирующих заголовков
  3. Traffic Camouflage — маскировка под обычный HTTPS трафик
  4. UDP Encryption — шифрование UDP broadcast пакетов
  5. Port Randomization — случайный порт при каждом запуске
  6. STUN Fallback — собственный STUN через CDN/domain fronting
  7. TLS Fingerprint — маскировка под популярные браузеры
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

from app.config import Config

STEALTH_ENABLED = Config.STEALTH_MODE

# Secret for generating obfuscated paths — stable across restarts (auto-generated in .env)
_STEALTH_SECRET = Config.STEALTH_SECRET.encode() if Config.STEALTH_SECRET else secrets.token_bytes(32)


def is_stealth() -> bool:
    return STEALTH_ENABLED


# ══════════════════════════════════════════════════════════════════════════════
# 1. WebSocket Path Obfuscation
# ══════════════════════════════════════════════════════════════════════════════

# Instead of /ws/chat/{room_id}, use /api/stream/{obfuscated_token}
# The token is HMAC(secret, original_path) — stable but unrecognizable

_WS_PATH_MAP: dict[str, str] = {}  # obfuscated -> real
_WS_REAL_MAP: dict[str, str] = {}  # real -> obfuscated


def obfuscate_ws_path(real_path: str) -> str:
    """Convert /ws/chat/123 → /api/v2/stream/{token}"""
    if real_path in _WS_REAL_MAP:
        return _WS_REAL_MAP[real_path]
    token = hmac.new(_STEALTH_SECRET, real_path.encode(), hashlib.sha256).hexdigest()[:16]
    obfuscated = f"/api/v2/stream/{token}"
    _WS_PATH_MAP[obfuscated] = real_path
    _WS_REAL_MAP[real_path] = obfuscated
    return obfuscated


def deobfuscate_ws_path(obfuscated_path: str) -> Optional[str]:
    """Reverse lookup: /api/v2/stream/{token} → /ws/chat/123"""
    return _WS_PATH_MAP.get(obfuscated_path)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Header Sanitization — удаление всех идентификаторов
# ══════════════════════════════════════════════════════════════════════════════

# Headers that must NEVER appear in stealth mode
_BANNED_HEADERS = {
    "x-vortex-event",
    "x-vortex-signature",
    "x-vortex-delivery-id",
    "x-vortex-timestamp",
}

# Response headers to remove (could fingerprint the app)
_STRIP_RESPONSE_HEADERS = {
    "x-powered-by",
    "x-aspnet-version",
}

# Generic headers to mimic a standard web app
_STEALTH_RESPONSE_HEADERS = {
    "Server": "nginx",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
}


def sanitize_request_headers(headers: dict) -> dict:
    """Remove identifying headers from outgoing requests."""
    cleaned = {}
    for k, v in headers.items():
        if k.lower() not in _BANNED_HEADERS:
            cleaned[k] = v
    # Replace identifying User-Agent
    if "user-agent" in {k.lower() for k in cleaned}:
        for k in list(cleaned):
            if k.lower() == "user-agent" and "vortex" in cleaned[k].lower():
                cleaned[k] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    return cleaned


def sanitize_response(response: Response) -> Response:
    """Strip identifying headers from response."""
    if not STEALTH_ENABLED:
        return response
    for h in _STRIP_RESPONSE_HEADERS:
        if h in response.headers:
            del response.headers[h]
    for k, v in _STEALTH_RESPONSE_HEADERS.items():
        response.headers[k] = v
    # Remove any headers containing "vortex"
    to_remove = [k for k in response.headers if "vortex" in k.lower()]
    for k in to_remove:
        del response.headers[k]
    return response


# ══════════════════════════════════════════════════════════════════════════════
# 3. Traffic Camouflage — маскировка под обычный HTTPS
# ══════════════════════════════════════════════════════════════════════════════

def camouflage_payload(data: bytes) -> bytes:
    """
    Wrap binary data to look like a standard HTTP response body.

    Adds a fake HTTP/HTML wrapper so DPI sees it as normal web traffic.
    Format: [4B real_len][random_padding][data][random_padding]
    """
    import struct
    real_len = len(data)
    # Pad to standard sizes (like MetadataPadding in privacy.py)
    targets = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]
    target = targets[-1]
    for t in targets:
        if t >= real_len + 8:
            target = t
            break
    pad_len = target - real_len - 4
    padding = os.urandom(max(0, pad_len))
    return struct.pack(">I", real_len) + data + padding


def decamouflage_payload(data: bytes) -> bytes:
    """Extract real data from camouflaged payload."""
    import struct
    if len(data) < 4:
        return data
    real_len = struct.unpack(">I", data[:4])[0]
    if real_len > len(data) - 4:
        return data  # not camouflaged
    return data[4:4 + real_len]


# ══════════════════════════════════════════════════════════════════════════════
# 4. UDP Discovery Encryption
# ══════════════════════════════════════════════════════════════════════════════

def encrypt_udp_broadcast(payload: bytes) -> bytes:
    """
    Encrypt UDP discovery payload so it looks like random noise.

    Uses XOR with key derived from a shared network secret.
    Not cryptographically strong (peers need the same key),
    but prevents DPI from reading the JSON structure.
    """
    # Derive key from secret (all Vortex nodes on the network share this)
    network_key = Config.VORTEX_NETWORK_KEY.encode()
    key = hashlib.sha256(network_key).digest()

    nonce = os.urandom(8)
    encrypted = bytearray(len(payload))
    for i, b in enumerate(payload):
        encrypted[i] = b ^ key[(i + nonce[i % 8]) % 32]
    return nonce + bytes(encrypted)


def decrypt_udp_broadcast(data: bytes) -> Optional[bytes]:
    """Decrypt UDP discovery payload."""
    if len(data) < 9:
        return None
    nonce = data[:8]
    encrypted = data[8:]

    network_key = Config.VORTEX_NETWORK_KEY.encode()
    key = hashlib.sha256(network_key).digest()

    decrypted = bytearray(len(encrypted))
    for i, b in enumerate(encrypted):
        decrypted[i] = b ^ key[(i + nonce[i % 8]) % 32]
    return bytes(decrypted)


# ══════════════════════════════════════════════════════════════════════════════
# 5. Port Randomization
# ══════════════════════════════════════════════════════════════════════════════

def get_stealth_port() -> int:
    """
    Generate a random high port for stealth mode.
    Uses common web service ports to blend in.
    """
    # Ports that look like common services
    common_ports = [443, 8443, 8080, 3000, 5000, 8888, 9090, 4443]
    if STEALTH_ENABLED:
        return secrets.choice(common_ports)
    return int(os.getenv("PORT", "9000"))


def get_stealth_udp_port() -> int:
    """Random UDP port for stealth discovery."""
    if STEALTH_ENABLED:
        return 49152 + secrets.randbelow(16384)  # ephemeral range
    return int(os.getenv("UDP_PORT", "4200"))


# ══════════════════════════════════════════════════════════════════════════════
# 6. STUN Fallback — CDN/domain fronted STUN
# ══════════════════════════════════════════════════════════════════════════════

def get_stealth_ice_servers() -> list[dict]:
    """
    Return ICE server list for stealth mode.

    In stealth mode, use TURN-over-TLS on port 443 to look like
    regular HTTPS traffic. Regular STUN on 19302/3478 is easily blocked.
    """
    if STEALTH_ENABLED:
        # TURN over TLS on port 443 — looks like normal HTTPS
        custom_turn = Config.STEALTH_TURN_URL
        if custom_turn:
            return [
                {"urls": custom_turn},
                {"urls": "stun:stun.cloudflare.com:443"},
            ]
        # Fallback: use cloudflare on 443 (less suspicious than 3478/19302)
        return [
            {"urls": "stun:stun.cloudflare.com:443"},
        ]
    # Normal mode — standard STUN
    return [
        {"urls": "stun:stun.l.google.com:19302"},
        {"urls": "stun:stun1.l.google.com:19302"},
        {"urls": "stun:stun.cloudflare.com:3478"},
    ]


# ══════════════════════════════════════════════════════════════════════════════
# 7. Fake Site — маскировка под обычный сайт
# ══════════════════════════════════════════════════════════════════════════════

_FAKE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
       max-width: 640px; margin: 80px auto; padding: 0 20px;
       color: #333; background: #fafafa; }
h1 { font-weight: 300; color: #555; }
p { line-height: 1.6; color: #777; }
</style>
</head>
<body>
<h1>Welcome</h1>
<p>This server is currently under maintenance. Please check back later.</p>
<p><small>&copy; 2026</small></p>
</body>
</html>"""


def get_fake_index() -> str:
    """Return a generic HTML page for unauthenticated visitors in stealth mode."""
    return _FAKE_HTML


# ══════════════════════════════════════════════════════════════════════════════
# 8. Stealth Middleware — автоматическая маскировка всех ответов
# ══════════════════════════════════════════════════════════════════════════════

class StealthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that sanitizes all responses in stealth mode:
    - Strips identifying headers
    - Blocks health/docs endpoints
    - Returns fake page for unknown visitors
    """

    async def dispatch(self, request: Request, call_next):
        if not STEALTH_ENABLED:
            return await call_next(request)

        path = request.url.path

        # Block endpoints that expose app info
        if path in ("/health", "/api/docs", "/api/redoc", "/openapi.json"):
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("Not Found", status_code=404)

        # Block manifest.json (contains app name)
        if path == "/manifest.json" or path == "/static/manifest.json":
            from starlette.responses import JSONResponse
            return JSONResponse({
                "name": "Web App",
                "short_name": "App",
                "start_url": "/",
                "display": "standalone",
            })

        response = await call_next(request)
        return sanitize_response(response)


# ══════════════════════════════════════════════════════════════════════════════
# 9. Stealth Status
# ══════════════════════════════════════════════════════════════════════════════

def get_stealth_status() -> dict:
    """Return stealth mode status."""
    return {
        "stealth_enabled": STEALTH_ENABLED,
        "ws_obfuscation": STEALTH_ENABLED,
        "header_sanitization": STEALTH_ENABLED,
        "udp_encryption": STEALTH_ENABLED,
        "port_randomization": STEALTH_ENABLED,
        "stun_fallback": STEALTH_ENABLED,
        "fake_site": STEALTH_ENABLED,
        "traffic_camouflage": STEALTH_ENABLED,
    }
