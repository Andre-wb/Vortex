# `node_setup/` — First-run Setup Wizard (legacy / server-side)

Browser-based setup wizard served by the node itself on first boot. Distinct from `vortex_wizard/`, which is the **desktop bundle** that wraps the same flow in a pywebview window — the two share concepts but have different surfaces.

This module is mounted into the main FastAPI app when the node detects it has no on-disk config. Once `config.yaml` + keys exist, the `/setup` routes are disabled.

## What it does

- Pick a port + bind address
- Generate or import Ed25519 node identity
- Configure SSL (self-signed / Let's Encrypt / import)
- Pick database backend (SQLite / PostgreSQL)
- Seed the controller pubkey + mirror URL list
- Optional: enable Tor hidden service, BMP, stealth level
- Writes `config.yaml` + keys and triggers a first clean restart

## Files

| File                | Role                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------ |
| `_app.py`           | FastAPI sub-app factory. Mounted at `/setup` on first run.                            |
| `wizard.py`         | Wizard state machine — step transitions, validation, persistence.                     |
| `wizard_routes.py`  | HTTP routes for each step (GET renders the page, POST validates and advances).        |
| `wizard_env.py`     | Writes `config.yaml` / `.env`, applies env variables, regenerates systemd unit.       |
| `models.py`         | Pydantic models for step payloads (PortStep, SSLStep, DBStep, FinalStep, …).         |
| `ssl_manager.py`    | Orchestrates `ssl_generate.py` (self-signed) or `ssl_install.py` (ACME / Let's Encrypt). |
| `ssl_generate.py`   | Generates a self-signed cert with sane defaults (RSA-4096 or ECDSA P-384).            |
| `ssl_install.py`    | Obtains a cert via ACME HTTP-01 or DNS-01; installs into `certs/`.                    |
| `ssl_utils.py`      | Helpers — fingerprint, PEM parsing, expiry checks.                                    |
| `ssl_result.py`     | Typed result object returned to the wizard.                                           |
| `static/` + `templates/` | UI assets for the wizard pages. `templates/setup.html` is the shell, `partials/` holds per-step fragments. |

## Flow

```
user opens https://host/   →  no config?  →  redirect /setup
                                               │
     POST /setup/network   ──►  chosen port + bind addr
     POST /setup/identity  ──►  generate or paste seed
     POST /setup/ssl       ──►  self-signed / ACME / import
     POST /setup/database  ──►  SQLite path or PG DSN
     POST /setup/peer      ──►  controller pubkey + mirrors
     POST /setup/extras    ──►  Tor / BMP / stealth
     POST /setup/finish    ──►  wizard_env.write() + systemctl restart
```

Every POST is idempotent — re-submitting a step just rewrites the partial state.

## Relation to `vortex_wizard/`

- `node_setup/` serves the **web UI** from inside the node process. Intended for server admins running via SSH + port-forward.
- `vortex_wizard/` is the **desktop GUI** bundle (PyInstaller, pywebview). Wraps essentially the same questions into a native-looking window. Shares the SSL and env-writing helpers via duplicated code — historical reason, kept deliberately so the two can diverge without binding the desktop release to a backend schema.

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
