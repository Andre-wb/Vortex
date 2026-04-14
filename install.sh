#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Vortex Messenger — One-line installer
# Usage: curl -fsSL https://your-domain/install.sh | bash
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

VORTEX_DIR="${VORTEX_DIR:-$(pwd)}"

# ── Detect OS ────────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Linux*)  PLATFORM=linux;;
    Darwin*) PLATFORM=macos;;
    *)       err "Unsupported OS: $OS"; exit 1;;
esac
info "Platform: $PLATFORM"

# ── Check Python 3.11+ ──────────────────────────────────────────────────────
PYTHON=""
for py in python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON="$py"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    err "Python 3.11+ required. Install it first:"
    if [ "$PLATFORM" = "macos" ]; then
        echo "  brew install python@3.12"
    else
        echo "  sudo apt install python3.12 python3.12-venv  # Debian/Ubuntu"
        echo "  sudo dnf install python3.12                    # Fedora"
    fi
    exit 1
fi
ok "Python: $($PYTHON --version)"

# ── Create virtual environment ───────────────────────────────────────────────
if [ ! -d "$VORTEX_DIR/venv" ]; then
    info "Creating virtual environment..."
    $PYTHON -m venv "$VORTEX_DIR/venv"
    ok "Virtual environment created"
else
    ok "Virtual environment exists"
fi

source "$VORTEX_DIR/venv/bin/activate"

# ── Install dependencies ─────────────────────────────────────────────────────
info "Installing dependencies..."
pip install --upgrade pip -q
pip install -r "$VORTEX_DIR/requirements.txt" -q 2>/dev/null || {
    warn "Some optional deps failed, installing core..."
    pip install fastapi uvicorn sqlalchemy cryptography httpx pydantic argon2-cffi \
        python-multipart aiofiles python-jose pywebpush -q
}
ok "Dependencies installed"

# ── Generate .env if missing ─────────────────────────────────────────────────
ENV_FILE="$VORTEX_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    info "Creating .env from template..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    CSRF_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    NODE_ID=$(python3 -c "import secrets; print(secrets.token_hex(16))")

    cat > "$ENV_FILE" <<ENVEOF
# Vortex Messenger Configuration
SECRET_KEY=$SECRET
JWT_SECRET=$JWT_SECRET
CSRF_SECRET=$CSRF_SECRET
NODE_ID=$NODE_ID
ENVIRONMENT=production

# Database (SQLite default, set DATABASE_URL for PostgreSQL)
# DATABASE_URL=postgresql://vortex:password@localhost:5432/vortex

# SSL (auto-generated if missing)
SSL_CERT=certs/vortex.crt
SSL_KEY=certs/vortex.key

# Network
HOST=0.0.0.0
PORT=8443
NETWORK_MODE=local

# AI (optional: ollama default, set for remote API)
# AI_PROVIDER=openai
# AI_API_KEY=sk-...
# AI_API_URL=https://api.openai.com/v1
# AI_MODEL=gpt-4o-mini

# SFU (optional: builtin default)
# SFU_MODE=mediasoup
# SFU_URL=http://localhost:3000
# SFU_API_KEY=

# Web Push (auto-generated on first run)
# VAPID_PRIVATE_KEY=
# VAPID_PUBLIC_KEY=
# VAPID_CONTACT=mailto:admin@example.com
ENVEOF
    ok "Created .env with secure random keys"
else
    ok ".env already exists"
fi

# ── Generate SSL certs if missing ────────────────────────────────────────────
CERT_DIR="$VORTEX_DIR/certs"
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/vortex.crt" ] || [ ! -f "$CERT_DIR/vortex.key" ]; then
    info "Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/vortex.key" \
        -out "$CERT_DIR/vortex.crt" -days 365 -nodes \
        -subj "/CN=vortex-node/O=Vortex/C=XX" 2>/dev/null
    ok "SSL certificate generated"
else
    ok "SSL certificates exist"
fi

# ── Initialize database ─────────────────────────────────────────────────────
info "Initializing database..."
python3 -c "from app.database import init_db; init_db()" 2>/dev/null && ok "Database initialized" || warn "Database init skipped (may need manual setup)"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Vortex installed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Start the server:"
echo "    source venv/bin/activate"
echo "    python run.py"
echo ""
echo "  Or with Docker:"
echo "    docker compose up -d"
echo ""
echo "  Open: https://localhost:8443"
echo ""
