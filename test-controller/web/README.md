# `test-controller/web/` — Test Controller Static Site

Static site for the lightweight test controller harness (`../server.py` serves it). A stripped-down copy of `vortex_controller/web/` used by the test suite to exercise the node's controller-client flow without needing a real controller running.

## Layout

```
web/
├── index.html               ← minimal landing
├── nodes.html, entries.html ← pages the node may hit
├── locales/                 ← minimal locale JSON
├── icons/                   ← minimal icon set
└── assets/                  ← CSS + JS
```

## When used

- Playwright / pytest integration tests that need a stub controller responding to `/v1/*`.
- Local dev without wanting to run a full PostgreSQL-backed controller.

## Differences from the real controller

- No signed responses — returns plain JSON. Good enough for tests that don't verify signatures. Tests that DO verify pin a fixed keypair instead.
- Reduced endpoint set — only the paths the test actively hits.
- No admin dashboard.

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
