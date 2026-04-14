from __future__ import annotations
import base64
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

_ENV = Path(".env")


def _read_env() -> None:
    if _ENV.exists():
        for line in _ENV.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


_read_env()


def _auto_secret(key: str) -> str:
    val = os.getenv(key)
    if not val:
        val = secrets.token_hex(32)
        with open(_ENV, "a") as f:
            f.write(f"\n{key}={val}\n")
        os.environ[key] = val
        # Ограничиваем права .env файла
        try:
            os.chmod(_ENV, 0o600)
        except OSError as _e:
            logger.warning("Could not restrict .env permissions to 0o600: %s", _e)
    return val


class Config:
    JWT_SECRET = _auto_secret("JWT_SECRET")
    CSRF_SECRET = _auto_secret("CSRF_SECRET")
    ACCESS_TOKEN_EXPIRE_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MIN", "60"))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "9000"))
    DEVICE_NAME = os.getenv("DEVICE_NAME", "")
    DB_PATH = os.getenv("DB_PATH", "vortex.db")
    # If DATABASE_URL is set, use it directly (e.g. postgresql://user:pass@host/db).
    # If empty, fall back to sqlite:///<DB_PATH>.
    # Alternatively, set POSTGRES_* env vars to auto-build a PostgreSQL URL.
    DATABASE_URL = os.getenv("DATABASE_URL", "")

    # ── PostgreSQL individual env vars (alternative to DATABASE_URL) ──────────
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB = os.getenv("POSTGRES_DB", "vortex")
    POSTGRES_USER = os.getenv("POSTGRES_USER", "vortex")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")

    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))
    DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))
    UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads"))
    KEYS_DIR = Path(os.getenv("KEYS_DIR", "keys"))
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    IS_PRODUCTION = ENVIRONMENT == "production"
    UDP_PORT = int(os.getenv("UDP_PORT", "4200"))
    UDP_INTERVAL_SEC = int(os.getenv("UDP_INTERVAL_SEC", "2"))
    PEER_TIMEOUT_SEC = int(os.getenv("PEER_TIMEOUT_SEC", "15"))
    MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "3072"))  # 3 GB default
    MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
    # ── Testing ──────────────────────────────────────────────────────────
    TESTING = os.getenv("TESTING", "").lower() == "true"

    _waf_default = "999999" if os.getenv("TESTING", "").lower() == "true" else "120"
    WAF_RATE_LIMIT_REQUESTS = int(os.getenv("WAF_RATE_LIMIT_REQUESTS", _waf_default))
    WAF_RATE_LIMIT_WINDOW = int(os.getenv("WAF_RATE_LIMIT_WINDOW", "60"))
    WAF_BLOCK_DURATION = int(os.getenv("WAF_BLOCK_DURATION", "3600"))

    # ── Global Mode ───────────────────────────────────────────────────────
    NETWORK_MODE = os.getenv("NETWORK_MODE", "local")  # "local" или "global"
    BOOTSTRAP_PEERS = os.getenv("BOOTSTRAP_PEERS", "")  # ip:port через запятую
    # Obfuscation disabled in TESTING mode to avoid probe detector blocking test requests
    OBFUSCATION_ENABLED = (
        os.getenv("OBFUSCATION_ENABLED", "true").lower() == "true"
        and os.getenv("TESTING", "").lower() != "true"
    )

    # BMP Delivery — route message delivery through Blind Mailbox Protocol
    BMP_DELIVERY_ENABLED = os.getenv("BMP_DELIVERY", "true").lower() in ("true", "1", "yes")

    # ── VAPID (Web Push) ─────────────────────────────────────────────────────
    VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
    VAPID_PUBLIC_KEY  = os.getenv("VAPID_PUBLIC_KEY", "")

    # ── Регистрация ──────────────────────────────────────────────────────────
    _raw_reg_mode = os.getenv("REGISTRATION_MODE", "open").strip().lower()
    REGISTRATION_MODE = _raw_reg_mode if _raw_reg_mode in ("open", "invite", "closed") else "closed"
    INVITE_CODE_NODE = os.getenv("INVITE_CODE_NODE", "").strip()  # код для регистрации (если invite mode)

    # ── Redis (Horizontal Scaling) ────────────────────────────────────────────
    REDIS_URL = os.getenv("REDIS_URL", "")  # redis://host:6379/0
    REDIS_POOL_SIZE = int(os.getenv("REDIS_POOL_SIZE", "10"))
    REDIS_CHANNEL_PREFIX = os.getenv("REDIS_CHANNEL_PREFIX", "vortex")

    # ── Privacy ─────────────────────────────────────────────────────────────
    STORE_IPS = os.getenv("STORE_IPS", "false").lower() != "false"
    HASH_IPS  = os.getenv("HASH_IPS", "true").lower() == "true"
    TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
    TOR_HIDDEN_SERVICE = os.getenv("TOR_HIDDEN_SERVICE", "false").lower() in ("1", "true", "yes")
    TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
    EPHEMERAL_IDENTITIES = os.getenv("EPHEMERAL_IDENTITIES", "false").lower() == "true"
    METADATA_PADDING = os.getenv("METADATA_PADDING", "true").lower() == "true"

    # ── Stealth Mode (disabled in TESTING to avoid blocking health/API endpoints) ─
    STEALTH_MODE = (
        os.getenv("STEALTH_MODE", "false").lower() in ("true", "1", "yes")
        and os.getenv("TESTING", "").lower() != "true"
    )
    STEALTH_SECRET = _auto_secret("STEALTH_SECRET")
    VORTEX_NETWORK_KEY = _auto_secret("VORTEX_NETWORK_KEY")
    STEALTH_TURN_URL = os.getenv("STEALTH_TURN_URL", "")

    # ── Pluggable Transports ──────────────────────────────────────────────────
    import secrets as _secrets
    SHADOWSOCKS_PASSWORD = os.getenv("SHADOWSOCKS_PASSWORD", "") or _secrets.token_urlsafe(32)
    BRIDGE_MODE = os.getenv("BRIDGE_MODE", "false").lower() == "true"
    DOMAIN_FRONT_HOST = os.getenv("DOMAIN_FRONT_HOST", "")  # e.g. "www.cloudflare.com"

    # ── CDN Relay (Multi-CDN) ────────────────────────────────────────────────
    CDN_RELAY_URL = os.getenv("CDN_RELAY_URL", "")
    CDN_RELAY_URLS = os.getenv("CDN_RELAY_URLS", os.getenv("CDN_RELAY_URL", ""))
    CDN_RELAY_SECRET = os.getenv("CDN_RELAY_SECRET", "") or _secrets.token_urlsafe(48)

    # ── Translation (LibreTranslate) ─────────────────────────────────────────
    TRANSLATE_URL = os.getenv("TRANSLATE_URL", "http://localhost:5000")
    TRANSLATE_ENABLED = os.getenv("TRANSLATE_ENABLED", "false").lower() == "true"

    # ── AI Assistant ────────────────────────────────────────────────────────
    OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
    AI_ENABLED   = os.getenv("AI_ENABLED",   "true").lower() != "false"
    AI_PROVIDER  = os.getenv("AI_PROVIDER",  "auto")  # auto/ollama/openai/anthropic
    AI_API_KEY   = os.getenv("AI_API_KEY",   "")
    AI_API_URL   = os.getenv("AI_API_URL",   "")
    AI_MODEL     = os.getenv("AI_MODEL",     "")

    # ── SFU (Selective Forwarding Unit) ─────────────────────────────────────
    SFU_MODE     = os.getenv("SFU_MODE",     "builtin")  # builtin/mediasoup/janus
    SFU_URL      = os.getenv("SFU_URL",      "")
    SFU_API_KEY  = os.getenv("SFU_API_KEY",  "")

    @classmethod
    def get_database_url(cls) -> str:
        """Resolve effective DATABASE_URL.

        Priority:
          1. DATABASE_URL env var (explicit, used as-is)
          2. POSTGRES_* env vars (auto-built postgresql:// URL)
          3. sqlite:///<DB_PATH> (default for local development)
        """
        if cls.DATABASE_URL:
            return cls.DATABASE_URL
        if cls.POSTGRES_PASSWORD:
            # POSTGRES_PASSWORD is set — build URL from individual vars
            return (
                f"postgresql://{cls.POSTGRES_USER}:{cls.POSTGRES_PASSWORD}"
                f"@{cls.POSTGRES_HOST}:{cls.POSTGRES_PORT}/{cls.POSTGRES_DB}"
            )
        return f"sqlite:///{cls.DB_PATH}"

    @classmethod
    def ensure_dirs(cls) -> None:
        cls.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        cls.KEYS_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def validate(cls) -> None:
        """Validate configuration values at startup. Logs warnings but never raises."""
        if not (1 <= cls.PORT <= 65535):
            logger.warning("Config: PORT=%d is out of valid range (1-65535)", cls.PORT)
        if len(cls.JWT_SECRET) < 32:
            logger.warning("Config: JWT_SECRET is too short (%d chars, need >= 32)", len(cls.JWT_SECRET))
        if len(cls.CSRF_SECRET) < 32:
            logger.warning("Config: CSRF_SECRET is too short (%d chars, need >= 32)", len(cls.CSRF_SECRET))
        db_parent = Path(cls.DB_PATH).parent
        if str(db_parent) != "." and not db_parent.exists():
            logger.warning("Config: DB_PATH parent directory does not exist: %s", db_parent)
        if cls.NETWORK_MODE not in ("local", "global"):
            logger.warning("Config: NETWORK_MODE=%r is invalid (expected 'local' or 'global')", cls.NETWORK_MODE)
        if cls.REGISTRATION_MODE not in ("open", "invite", "closed"):
            logger.warning("Config: REGISTRATION_MODE=%r is invalid (expected 'open', 'invite', or 'closed')", cls.REGISTRATION_MODE)
        if not (1 <= cls.MAX_FILE_MB <= 10000):
            logger.warning("Config: MAX_FILE_MB=%d is out of valid range (1-10000)", cls.MAX_FILE_MB)


def _ensure_vapid_keys() -> None:
    """Generate VAPID ECDSA P-256 keypair if not present in environment."""
    if os.getenv("VAPID_PUBLIC_KEY"):
        return
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        private_key = ec.generate_private_key(ec.SECP256R1())

        # Private key as PEM (newlines replaced with | for single-line .env storage)
        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        # Public key as uncompressed point, base64url encoded (no padding)
        pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        pub_b64 = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()

        priv_env = priv_pem.replace("\n", "|")
        with open(_ENV, "a") as f:
            f.write(f"\nVAPID_PRIVATE_KEY={priv_env}\n")
            f.write(f"VAPID_PUBLIC_KEY={pub_b64}\n")
        try:
            os.chmod(_ENV, 0o600)
        except OSError as _e:
            logger.warning("Could not restrict .env permissions to 0o600: %s", _e)

        os.environ["VAPID_PRIVATE_KEY"] = priv_pem
        os.environ["VAPID_PUBLIC_KEY"] = pub_b64
        Config.VAPID_PRIVATE_KEY = priv_pem
        Config.VAPID_PUBLIC_KEY = pub_b64
    except Exception as e:
        logger.warning("Failed to generate VAPID keys: %s", e)


_ensure_vapid_keys()