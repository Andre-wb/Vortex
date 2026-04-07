# Vortex — Quick Start Guide

## Prerequisites

- Python 3.10+
- Node.js 18+ (for frontend tooling)
- PostgreSQL 14+ or SQLite (development)
- Redis (optional, for horizontal scaling)
- liboqs-python (post-quantum cryptography)

## Installation

```bash
# Clone the repository
git clone https://github.com/vortex-messenger/vortex.git
cd vortex

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Generate keys
python -c "from app.keys.keys import generate_node_keypair; generate_node_keypair()"

# Run
python run.py
```

Server starts at `https://localhost:8443`.

## Configuration

Key environment variables (`.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///vortex.db` | Database connection string |
| `JWT_SECRET` | (generated) | JWT signing key |
| `STORE_IPS` | `true` | Set `false` for zero-IP mode |
| `HASH_IPS` | `false` | HMAC-hash IPs for rate limiting |
| `TOR_HIDDEN_SERVICE` | `false` | Enable automatic .onion address |
| `STEG_KEY` | (random) | Steganography shared key |
| `FEDERATION_ENABLED` | `true` | Enable inter-node federation |

## First Steps

1. **Register**: `POST /api/authentication/register` with `{username, password}`
2. **Login**: `POST /api/authentication/login` → receive JWT token
3. **Create room**: `POST /api/rooms/create` with `{name, description}`
4. **Connect WebSocket**: `WSS /ws/{room_id}` with cookie `access_token`
5. **Send message**: WebSocket JSON `{type: "message", content_encrypted: "<base64>"}`

## API Documentation

- **Swagger UI**: `/api/docs`
- **ReDoc**: `/api/redoc`
- **OpenAPI JSON**: `/openapi.json`

## Running Tests

```bash
# All tests
python -m pytest app/tests/ -x -q

# With coverage
python -m pytest app/tests/ --cov=app --cov-report=term-missing

# Specific module
python -m pytest app/tests/test_crypto.py -v
```

## Docker

```bash
docker build -t vortex .
docker run -p 8443:8443 -e JWT_SECRET=your-secret vortex
```

## Mobile (Capacitor)

```bash
npm install
npx cap add ios
npx cap add android
npx cap sync
npx cap open ios      # Opens Xcode
npx cap open android  # Opens Android Studio
```

## Desktop (Tauri)

```bash
cd src-tauri
cargo tauri dev      # Development
cargo tauri build    # Production build
```
