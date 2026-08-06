# `node_setup/templates/partials/` — Per-step Form Fragments

Jinja fragments, one per wizard step. Included from `../setup.html` based on the wizard's current state.

## Fragments (typical)

- `network.html`    — port + bind address.
- `identity.html`   — seed generate / paste.
- `ssl.html`        — self-signed vs ACME vs import.
- `database.html`   — DB backend + test connection.
- `peer.html`       — controller pubkey + mirror URLs.
- `extras.html`     — Tor / BMP / stealth toggles.
- `finalize.html`   — review + commit.
- `done.html`       — success screen + redirect.

## Convention

- Each fragment renders one form.
- The form POSTs to `/setup/<step>` — handled by `../../wizard_routes.py`.
- No JavaScript required — each step is usable as a plain HTML form.

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
