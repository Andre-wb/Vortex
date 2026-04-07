```
  ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

<h1 align="center">VORTEX</h1>

<p align="center">
  <b>Fully decentralized P2P messenger with end-to-end encryption, mesh networking, and zero central servers</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Rust-1.75+-DEA584?style=for-the-badge&logo=rust&logoColor=black" alt="Rust">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/WebRTC-P2P-333333?style=for-the-badge&logo=webrtc&logoColor=white" alt="WebRTC">
  <img src="https://img.shields.io/badge/Tauri-5.0-FFC131?style=for-the-badge&logo=tauri&logoColor=black" alt="Tauri">
  <img src="https://img.shields.io/badge/Version-5.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/License-Apache_2.0-D22128?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/X25519-ECDH-green?style=flat-square" alt="X25519">
  <img src="https://img.shields.io/badge/AES--256--GCM-Encryption-green?style=flat-square" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/Kyber--768-Post--Quantum-green?style=flat-square" alt="Kyber-768">
  <img src="https://img.shields.io/badge/Argon2id-Hashing-green?style=flat-square" alt="Argon2id">
  <img src="https://img.shields.io/badge/BLAKE3-MAC-green?style=flat-square" alt="BLAKE3">
  <img src="https://img.shields.io/badge/128-Languages-green?style=flat-square" alt="128 Languages">
</p>

---

## What is Vortex

Vortex is a fully decentralized peer-to-peer messenger built from scratch without central servers, blockchains, or any intermediaries. Every device running Vortex is both a client and a server — a full node in a mesh network. Nodes discover each other on a local network via UDP broadcast in ~2 seconds, and in global mode they form a mesh network over the internet using a gossip protocol.

The server stores **only encrypted data** and physically cannot decrypt a single message — private keys never leave the device. Room key distribution uses ECIES (Elliptic Curve Integrated Encryption Scheme), where each room key is individually encrypted for each participant using their X25519 public key.

```
       ┌──────────┐              ┌──────────┐              ┌──────────┐
       │  Node A  │◄────────────►│  Node B  │◄────────────►│  Node C  │
       │ (Alice)  │   E2E        │ (Bob)    │   E2E        │ (Carol)  │
       │ :9000    │   encrypted  │ :9001    │   encrypted  │ :9002    │
       └────┬─────┘              └────┬─────┘              └────┬─────┘
            │                         │                         │
            │   ┌─────────────────────┼─────────────────────┐   │
            │   │     UDP Broadcast   │   Discovery         │   │
            │   │     ← 2 sec →       │                     │   │
            │   └─────────────────────┼─────────────────────┘   │
            │                         │                         │
            ▼                         ▼                         ▼
       ┌──────────┐              ┌──────────┐              ┌──────────┐
       │  SQLite  │              │  SQLite  │              │  SQLite  │
       │ (E2E DB) │              │ (E2E DB) │              │ (E2E DB) │
       └──────────┘              └──────────┘              └──────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### One-command setup

```bash
git clone https://github.com/BorisMalts/Vortex.git && cd Vortex && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && python3 run.py
```

### Step by step

```bash
# 1. Clone
git clone https://github.com/BorisMalts/Vortex.git
cd Vortex

# 2. Virtual environment
python3 -m venv .venv
source .venv/bin/activate    # macOS/Linux
# .venv\Scripts\activate     # Windows

# 3. Dependencies
pip install -r requirements.txt

# 4. Run
python3 run.py
```

The app starts at `https://localhost:8000`. Open it in a browser to begin.

### Desktop App (Tauri)

```bash
cd src-tauri
cargo tauri dev
```

Builds a native desktop app for macOS, Windows, and Linux.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, SQLAlchemy, PostgreSQL/SQLite, Uvicorn |
| **Frontend** | Vanilla JS (170+ modules), WebRTC, PWA |
| **Desktop** | Tauri v5 (Rust + WebView) |
| **Crypto** | X25519, AES-256-GCM, Argon2id, BLAKE3, Kyber-768 (Post-Quantum) |
| **Transport** | WebSocket, HTTP/2, SSE, BLE, Wi-Fi Direct, Tor |
| **Rendering** | Liquid-Glass-PRO (WebGL2 glass morphism) |
| **Bot Language** | Gravitix (custom Rust DSL) |
| **UI Framework** | Architex (declarative TypeScript DSL) |
| **Localization** | 128 languages with dynamic loading |
| **Testing** | pytest (40+ suites), Jest, Playwright |

---

## Features

### Messaging
- End-to-end encrypted messages (AES-256-GCM per room)
- Direct messages, groups, channels, forums, voice channels
- Thread replies, message editing, reactions, pins
- Polls (anonymous, quiz mode, multiple answers, time limits, participant suggestions)
- Scheduled messages and self-destructing messages
- File attachments with resumable chunked upload
- Voice messages with waveform visualization
- Rich link previews and @mentions
- Full-text message search
- Message translation (auto-detect language)

### Groups & Channels
- Role-based access control (owner, admin, member)
- Anti-spam bot with configurable rules
- Slow mode, auto-delete, invite codes
- Channel author management (add/remove authors)
- Discussion threads under channel posts
- RSS autoposting and webhook integration
- Room themes (custom wallpapers, accent colors, dark mode)
- Public room catalog with search and filters

### Live Streaming
- Full streaming system for channels (not just a video call)
- Host/co-host/speaker/viewer roles with real-time permission management
- Screen sharing and camera switching during stream
- Raise hand to request speaking permission
- Live reactions (floating emoji overlay)
- Donation system with linked payment card
- Stream chat (separate from room chat)
- Stream settings modal before going live
- Viewer count and peak tracking
- Auto-accept speakers option

### Voice & Video Calls
- 1:1 voice and video calls (WebRTC peer-to-peer)
- Group calls with up to 100 participants
- Adaptive topology: mesh (≤6 people) or SFU (7+)
- Persistent voice channels (Discord-style, join/leave freely)
- Screen sharing with bandwidth adaptation
- Dominant speaker detection
- Call recording (client-side, encrypted)
- Stage mode (webinars: speakers + listeners)
- Background blur and virtual backgrounds

### Spaces
- Nested organizational spaces (like Discord servers)
- Permission inheritance across rooms
- Member teams and announcements
- Space discovery and templates
- Analytics and audit logs

### Stories & Status
- 24-hour disappearing stories
- Custom status with emoji
- Presence indicators (online, away, DND, invisible)

### Bots & IDE
- Built-in bot marketplace
- Gravitix: custom bot programming language (Rust-based)
- In-app IDE with syntax highlighting, linting, file tree
- Bot state machines, NLU, webhooks, databases
- Pomodoro timer and zen mode in IDE

### Contacts & Social
- Contact list with sync
- User profiles (avatar, bio, birthday, shared media)
- Block list and report system
- QR code sharing for invites
- Global search (users, channels, rooms across mesh)

### Files & Media
- Encrypted file storage
- Image gallery with lightbox viewer
- Photo editor (crop, filters, draw)
- GIF picker
- Custom sticker packs
- Emoji picker

---

## Security

### Cryptographic Protocols

| Protocol | Purpose |
|----------|---------|
| **X25519** | Elliptic-curve Diffie-Hellman key exchange |
| **AES-256-GCM** | Symmetric message encryption |
| **ECIES** | Room key distribution (encrypted per member) |
| **Argon2id** | Password hashing (memory-hard) |
| **BLAKE3** | Message authentication codes |
| **HKDF-SHA256** | Key derivation |
| **Kyber-768** | Post-quantum key encapsulation (NIST FIPS 203) |
| **BIP39** | 24-word seed phrase for key recovery |

### Infrastructure Security

- **WAF (Web Application Firewall)** — SQL injection, XSS, CSRF, path traversal detection
- **Rate limiting** — per-endpoint and per-user token bucket
- **CAPTCHA** — bot protection on registration
- **CSP & Security Headers** — Content-Security-Policy, HSTS, X-Frame-Options
- **Sealed sender** — anonymous message delivery
- **IP privacy** — IP masking between peers
- **Traffic obfuscation** — disguises traffic as regular HTTPS to bypass DPI
- **Tor hidden service** — onion routing support
- **Panic button** — emergency data wipe
- **Canary tokens** — breach detection
- **GDPR compliance** — data export and deletion routes
- **Certificate pinning** — SSL/TLS with self-signed CA

### Key Management

- Keys generated on-device, never transmitted in plaintext
- Room keys encrypted individually for each participant via ECIES
- Key rotation on member leave (forward secrecy)
- Encrypted key backup with passphrase (cross-device sync)
- Fingerprint verification (safety numbers)

---

## Network & Transport

Vortex supports two operating modes:

### Local Mode (LAN)
- UDP broadcast peer discovery (~2 seconds)
- Direct HTTPS connections between nodes
- BLE GATT transport (Bluetooth Low Energy)
- Wi-Fi Direct (P2P mesh without router)
- Zero configuration required

### Global Mode (Internet)
- Gossip protocol for mesh formation
- Multi-hop routing (A → B → C)
- Store-and-forward for offline peers
- Cover traffic (anti-surveillance padding)
- Steganography (hidden data in images)
- Pluggable transports (domain fronting, CDN relay)
- Port knocking authentication
- NAT traversal (UPnP/PCP)
- Smart relay with adaptive routing

### Federation
- Server-to-server communication
- Remote room joining across nodes
- Peer registry with edge caching
- Redis pub/sub for horizontal scaling

---

## Architecture

```
Vortex/
├── app/                          # Backend (FastAPI)
│   ├── authentication/           # Login, register, 2FA, passkeys, QR
│   ├── chats/                    # Messages, rooms, calls, stream, voice
│   │   ├── messages/             # WebSocket chat, polls, reactions
│   │   ├── rooms/                # CRUD, members, keys, themes
│   │   ├── stream.py             # Live streaming system
│   │   ├── voice.py              # Persistent voice channels
│   │   ├── group_calls.py        # Group call management
│   │   ├── sfu.py                # Selective Forwarding Unit
│   │   └── ...                   # Channels, DMs, stories, bots, AI
│   ├── security/                 # Crypto, WAF, key backup, privacy
│   ├── transport/                # BLE, Wi-Fi Direct, Tor, obfuscation
│   ├── peer/                     # P2P discovery, federation, registry
│   ├── bots/                     # Bot runtime, anti-spam, marketplace
│   ├── models/                   # SQLAlchemy ORM models
│   └── tests/                    # 40+ test suites
├── static/
│   ├── js/                       # 170+ frontend modules
│   │   ├── chat/                 # Messaging, emoji, file upload, threads
│   │   ├── rooms/                # Room management, info, search
│   │   ├── ide/                  # Built-in code editor
│   │   ├── stream.js             # Streaming client
│   │   ├── webrtc.js             # 1:1 calls
│   │   ├── group_call.js         # Group calls
│   │   ├── voice_channel.js      # Voice channels
│   │   ├── crypto.js             # Client-side encryption
│   │   └── ...
│   ├── css/                      # 36 stylesheet files
│   └── locales/                  # 128 language JSON files
├── templates/                    # Jinja2 HTML templates
│   ├── screens/                  # Chat, settings, IDE, calls, voice
│   ├── modals/                   # Create room, stickers, gallery, etc.
│   └── components/               # Sidebar, stream, group call, etc.
├── Gravitix/                     # Bot programming language (Rust)
├── Liquid-Glass-PRO/             # WebGL2 glass morphism rendering
├── Architex/                     # Declarative UI framework (TypeScript)
├── node_setup/                   # Setup wizard (SSL, env, onboarding)
├── src-tauri/                    # Desktop app (macOS, Windows, Linux)
├── alembic/                      # Database migrations
├── e2e/                          # Playwright browser tests
└── run.py                        # Entry point
```

---

## Subprojects

### Gravitix — Bot Programming Language

A domain-specific language written in Rust for building chat bots. Compiles to an AST and runs in a sandboxed interpreter.

```gravitix
on message "hello" {
    reply "Hello, {user.name}!"
}

on command "/weather" {
    let city = args[0]
    let data = http.get("https://api.weather.com/{city}")
    reply "Weather in {city}: {data.temp}°C"
}
```

**Features:** Variables, functions, handlers, finite state machines, NLU, webhooks, databases, middleware, circuit breakers, testing framework, REPL, LSP server.

### Liquid-Glass-PRO — WebGL2 Rendering

Physically-based glass morphism effects using WebGL2 shaders. 12 glass variants with real-time refraction, Beer-Lambert absorption, Sellmeier dispersion, thin-film iridescence, chromatic aberration, Fresnel reflection, and caustics. Falls back to CSS blur on unsupported devices.

### Architex — UI Framework

A declarative TypeScript DSL for building mini-app interfaces inside Vortex. Component composition with JSX-like syntax, runtime transpilation, and responsive layouts.

---

## Localization

Vortex supports **128 languages** with full UI coverage including Russian, English, Ukrainian, Chinese, Spanish, German, French, Portuguese, Japanese, Korean, Arabic, Hindi, Turkish, Polish, Dutch, Italian, Thai, Vietnamese, Indonesian, Swahili, and 108 more — including regional languages like Chechen, Bashkir, Tatar, Sakha, Buryat, Tuvan, Crimean Tatar, Uyghur, Tibetan, Quechua, Guarani, Hawaiian, and constructed languages (Esperanto, Toki Pona, Latin).

The i18n system uses dynamic JSON loading with fallback cascade, interpolation, RTL detection, and localStorage persistence.

---

## Testing

```bash
# Run all tests
python3 -m pytest

# With coverage
python3 -m pytest --cov=app --cov-report=html

# Specific suite
python3 -m pytest app/tests/test_auth_core.py -v

# E2E browser tests (requires Playwright)
npx playwright test
```

**40+ test suites** covering: authentication, encryption, rooms, calls, channels, federation, bots, files, transport, security, key backup, post-quantum crypto, WebSocket, and integration flows.

---

## Configuration

Environment variables (`.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Bind port |
| `DATABASE_URL` | `sqlite:///vortex.db` | Database connection string |
| `SECRET_KEY` | (generated) | JWT signing key |
| `NETWORK_MODE` | `local` | `local` (LAN) or `global` (internet) |
| `SSL_CERT` | `certs/vortex.crt` | SSL certificate path |
| `SSL_KEY` | `certs/vortex.key` | SSL private key path |
| `SFU_THRESHOLD` | `6` | Participant count to switch from mesh to SFU |
| `WAF_RATE_LIMIT_REQUESTS` | `100` | Requests per window |
| `WAF_RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |
| `REDIS_URL` | (none) | Redis URL for horizontal scaling |
| `SENTRY_DSN` | (none) | Sentry error tracking |

---

## API Overview

Vortex exposes **200+ REST endpoints** and **5 WebSocket channels**:

| Category | Endpoints | Description |
|----------|-----------|-------------|
| Authentication | 15 | Login, register, 2FA, passkeys, QR, sessions |
| Rooms | 22 | Create, join, leave, settings, members, keys |
| Messages | 12 | Send, edit, delete, search, reactions, polls |
| Channels | 8 | Subscribe, post, feeds, autoposting |
| Voice | 14 | Join, leave, mute, stage mode, recording, SFU |
| Calls | 10 | Start, end, history, group calls |
| Streaming | 12 | Start, stop, join, permissions, reactions, donations |
| Contacts | 6 | Add, remove, block, search |
| Files | 7 | Upload (chunked), download, gallery |
| Bots | 10 | Create, deploy, marketplace, commands |
| Spaces | 8 | Create, join, manage, nested hierarchy |
| Stories | 4 | Create, view, delete |
| Security | 8 | Key backup, fingerprints, panic, GDPR |

**WebSocket channels:**
- `/ws/chat/{room_id}` — real-time messaging
- `/ws/signal/{room_id}` — WebRTC signaling (calls)
- `/ws/stream/{room_id}` — live stream signaling + events
- `/ws/voice-signal/{room_id}` — voice channel mesh signaling
- `/ws/notifications` — global push notifications

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
