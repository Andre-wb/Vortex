# `vortex_wizard/web/admin/` — Operator Dashboard Pages

Pages shown after first-run setup completes — the operator dashboard. Accessible from the wizard's main menu once a node is configured and running.

## Typical pages

- `overview.html`   — live stats: requests/sec, errors/sec, peer count, connected WS, DB health.
- `settings.html`   — live settings editor (calls `/api/settings/*`).
- `peers.html`      — discovered + trusted-federation peers; manual pin + unpin.
- `security.html`   — BMP / stealth / Tor / WAF live toggles, secret rotation.
- `backup.html`     — run now / schedule / restore.
- `database.html`   — vacuum, reindex, table sizes, slow-query snapshot.
- `logs.html`       — tail + grep.
- `diagnostics.html`— profile, hardware probe, env dump.
- `seed.html`       — BIP39 derive demo, Shamir split, key-backup vault status.
- `multidevice.html`— device-linking flow.
- `audit.html`      — append-only action log inside the wizard.
- `about.html`      — version + integrity report + credits.

## Convention

- Pages auth against the node's admin token (saved once during setup into the OS keychain).
- Long-running operations (big backup, integrity re-sign) dispatch to `../../api/ops_jobs.py` and poll progress via SSE.
- Never store secrets in `localStorage`; use the platform keychain bridge exposed by pywebview.

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
