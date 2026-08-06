# Vortex Controller

Discovery / registry service for Vortex nodes. Control plane only — does NOT
relay messaging traffic.

## What it does

- Accepts node registrations (with Ed25519 signature)
- Stores approved nodes (pubkey + endpoints) in **PostgreSQL** (SQLite for dev)
- Serves random approved nodes to clients (bootstrap)
- Publishes a signed list of entry URLs (for clients that can't resolve the
  controller domain directly — e.g. `trycloudflare` tunnels)

## Running

```bash
cd vortex_controller
pip install -r requirements.txt

# PostgreSQL (production)
export DATABASE_URL="postgresql://vortex:pw@localhost:5432/vortex_controller"
# — or individual vars:
export POSTGRES_HOST=localhost
export POSTGRES_USER=vortex
export POSTGRES_PASSWORD=pw
export POSTGRES_DB=vortex_controller

python -m vortex_controller.main
```

Listens on `0.0.0.0:8800`. The Ed25519 keypair is generated on first run at
`keys/controller.key` — **print the pubkey** shown in the log and pin it in
your Vortex clients.

### Creating the PostgreSQL database

```sql
CREATE DATABASE vortex_controller;
CREATE USER vortex WITH PASSWORD 'pw';
GRANT ALL PRIVILEGES ON DATABASE vortex_controller TO vortex;
```

The schema (nodes table) is created automatically on first start.

### SQLite fallback (development only)

If no `DATABASE_URL` / `POSTGRES_*` vars are set, the controller falls back to
`sqlite+aiosqlite:///controller.db`. **Not recommended for production** — use
PostgreSQL for concurrent writes.

### Environment

| Var | Default | Purpose |
|-----|---------|---------|
| `CONTROLLER_HOST` | `0.0.0.0` | Bind host |
| `CONTROLLER_PORT` | `8800` | Bind port |
| `CONTROLLER_KEYS_DIR` | `keys/` | Controller keypair directory |
| `AUTO_APPROVE` | `true` | Auto-approve registering nodes |
| `ENTRY_URLS` | — | Comma-separated bootstrap URLs |
| `DATABASE_URL` | — | SQLAlchemy URL (preferred) |
| `POSTGRES_HOST/PORT/USER/PASSWORD/DB` | — | Individual PG vars |
| `CONTROLLER_DB` | `controller.db` | SQLite fallback path |

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/register` | Node self-registers (with signature) |
| `POST` | `/v1/heartbeat` | Liveness ping (with signature) |
| `GET`  | `/v1/nodes/random?count=N` | N random approved online nodes |
| `GET`  | `/v1/nodes/lookup/{pubkey}` | Resolve a specific node |
| `GET`  | `/v1/entries` | Signed bootstrap entry URLs |
| `GET`  | `/v1/health` | Liveness + stats |

All responses are JSON; `/v1/entries`, `/v1/nodes/random`, and
`/v1/nodes/lookup` responses include a controller Ed25519 signature so clients
can verify authenticity even if the channel is compromised.

## Trust model

- Controller's public key is pinned into the Vortex client at release time.
- Nodes prove pubkey ownership by signing the registration payload.
- Clients verify controller signatures on all responses.
- Controller never sees messaging traffic — only metadata.

---

## License

Vortex is **dual-licensed** under the **GNU Affero General Public License
v3.0-or-later** (see `LICENSE`) or a **commercial license** (see
`LICENSE-COMMERCIAL.md`).

```
Copyright (C) 2026 Andrey Karavaev, Boris Maltsev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

## Authors

**Boris Maltsev**

[![GitHub](https://img.shields.io/badge/GitHub-BorisMalts-181717?style=flat-square&logo=github)](https://github.com/BorisMalts)

**Andrey Karavaev**

[![GitHub](https://img.shields.io/badge/GitHub-Andre--wb-181717?style=flat-square&logo=github)](https://github.com/Andre-wb)
