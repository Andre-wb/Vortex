# `node_setup/templates/` — First-run Wizard Templates

Jinja2 templates for the server-side first-run wizard (see `../README.md`).

## Files

| File                   | Role                                                                           |
| ---------------------- | ------------------------------------------------------------------------------ |
| `setup.html`           | Shell for the whole wizard — progress ribbon + step container.                 |
| `partials/`            | Per-step fragments included from `setup.html` based on current wizard state.   |

## Partials

Each partial is a self-contained form for one step:

- `network.html`      — port + bind address.
- `identity.html`     — generate or paste seed.
- `ssl.html`          — pick SSL path (self-signed / ACME / import).
- `database.html`     — pick backend + test connection.
- `peer.html`         — controller pubkey + mirror URLs.
- `extras.html`       — Tor / BMP / stealth toggles.
- `finalize.html`     — review + commit.
- `done.html`         — success screen, redirects to the main UI.

(Exact file list may vary — check the directory listing for the shipped set.)

## Convention

- Partials only accept the current state via the Python-side `wizard.py` state machine; they don't fetch anything of their own.
- Every form POSTs back to `/setup/<step>`; `wizard_routes.py` validates, updates state, and re-renders the next step.
- No JS dependencies — these pages are usable in `curl` + `w3m` if needed.

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
