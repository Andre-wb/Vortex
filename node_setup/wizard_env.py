# node_setup/wizard_env.py
# ==============================================================================
# Функции для чтения и записи .env файла конфигурации узла.
# ==============================================================================

from __future__ import annotations

import secrets
import time
from pathlib import Path

from .models import NodeConfig, SSOConfig
from ._app import ENV_FILE


def _read_env_dict() -> dict[str, str]:
    """Читает текущий .env файл и возвращает словарь переменных."""
    if not ENV_FILE.exists():
        return {}
    result = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def _write_env(cfg: NodeConfig) -> None:
    """
    Записывает (или перезаписывает) .env файл с параметрами узла.
    Генерирует новые секреты, если их нет в существующем файле.
    """
    existing = _read_env_dict()

    jwt_secret  = existing.get("JWT_SECRET")  or secrets.token_hex(32)
    csrf_secret = existing.get("CSRF_SECRET") or secrets.token_hex(32)
    sealed_secret = existing.get("SEALED_SENDER_SECRET") or secrets.token_hex(32)

    lines = [
        "# ⚡ VORTEX Node Configuration",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "# Security (DO NOT SHARE)",
        f"JWT_SECRET={jwt_secret}",
        f"CSRF_SECRET={csrf_secret}",
        f"SEALED_SENDER_SECRET={sealed_secret}",
        "",
        "# Tokens",
        f"ACCESS_TOKEN_EXPIRE_MIN=1440",
        f"REFRESH_TOKEN_EXPIRE_DAYS=30",
        "",
        "# Server",
        f"HOST={cfg.host}",
        f"PORT={cfg.port}",
        f"DEVICE_NAME={cfg.device_name}",
        f"ENVIRONMENT={cfg.environment}",
        "",
        "# Storage",
        f"DB_PATH=vortex.db",
        f"UPLOAD_DIR=uploads",
        f"KEYS_DIR=keys",
        f"MAX_FILE_MB={cfg.max_file_mb}",
        "",
        "# P2P Discovery",
        f"UDP_PORT={cfg.udp_port}",
        f"UDP_INTERVAL_SEC=2",
        f"PEER_TIMEOUT_SEC=15",
        "",
        "# WAF",
        f"WAF_RATE_LIMIT_REQUESTS=120",
        f"WAF_RATE_LIMIT_WINDOW=60",
        f"WAF_BLOCK_DURATION=3600",
        "",
        "# Network Mode",
        f"NETWORK_MODE={cfg.network_mode}",
        f"OBFUSCATION_ENABLED={'true' if cfg.obfuscation_enabled and cfg.network_mode == 'global' else 'false'}",
        f"REGISTRATION_MODE={cfg.registration_mode}",
        "",
        "# Stealth Mode (anti-censorship / DPI bypass)",
        f"STEALTH_MODE=true",
        f"STEALTH_SECRET={existing.get('STEALTH_SECRET') or secrets.token_hex(32)}",
        f"VORTEX_NETWORK_KEY={existing.get('VORTEX_NETWORK_KEY') or secrets.token_hex(32)}",
        f"STEALTH_TURN_URL=",
    ]
    if cfg.invite_code:
        lines.append(f"INVITE_CODE_NODE={cfg.invite_code}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_sso_env(cfg: SSOConfig) -> None:
    """Дописывает SSO/OAuth конфигурацию в .env файл."""
    lines: list[str] = ["\n# SSO / Authentication\n"]
    lines.append(f"PASSKEYS_ENABLED={'true' if cfg.passkeys_enabled else 'false'}\n")

    for p in cfg.providers:
        if p.type == "google":
            lines += [
                f"SSO_GOOGLE_CLIENT_ID={p.client_id}\n",
                f"SSO_GOOGLE_CLIENT_SECRET={p.client_secret}\n",
            ]
        elif p.type == "github":
            lines += [
                f"SSO_GITHUB_CLIENT_ID={p.client_id}\n",
                f"SSO_GITHUB_CLIENT_SECRET={p.client_secret}\n",
            ]
        elif p.type == "apple":
            pk_inline = p.private_key.replace("\n", "\\n")
            lines += [
                f"SSO_APPLE_CLIENT_ID={p.client_id}\n",
                f"SSO_APPLE_TEAM_ID={p.team_id}\n",
                f"SSO_APPLE_KEY_ID={p.key_id}\n",
                f"SSO_APPLE_PRIVATE_KEY={pk_inline}\n",
            ]
        elif p.type == "microsoft":
            lines += [
                f"SSO_MICROSOFT_TENANT_ID={p.tenant_id}\n",
                f"SSO_MICROSOFT_CLIENT_ID={p.client_id}\n",
                f"SSO_MICROSOFT_CLIENT_SECRET={p.client_secret}\n",
            ]
        elif p.type in ("oidc", "keycloak"):
            lines += [
                f"SSO_OIDC_DISCOVERY_URL={p.discovery_url}\n",
                f"SSO_OIDC_CLIENT_ID={p.client_id}\n",
                f"SSO_OIDC_CLIENT_SECRET={p.client_secret}\n",
            ]

    with open(ENV_FILE, "a", encoding="utf-8") as f:
        f.writelines(lines)
