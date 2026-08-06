# `node_setup/static/` — First-run Wizard Assets (CSS + JS)

Static assets for the **server-side** first-run wizard (see `../README.md`). Served at `/setup/static/*` while the node has no `config.yaml`; after first successful finish, the setup routes and this directory stop being served.

## Layout

```
static/
├── css/            ← wizard-specific stylesheets (setup form, progress ribbon)
└── js/             ← step validators, form helpers, SSE progress updates
```

## Why it's separate from `../../static/`

- The main web UI (`../../static/`) is large — 41 CSS files, 65+ JS modules, 146 locale files, vendored third-party libs. Loading it for a 5-minute setup flow is overkill.
- The setup wizard must work **without** a configured database or any of the feature modules — so it can't depend on any asset that assumes the node is bootstrapped.
- Keeping the setup UI self-contained also means operators running `python -m node_setup` manually get a predictable experience without any hidden dependency on the main site.

## Conventions

- Vanilla JS, no framework.
- Each step's JS module binds to the form on that step only; no shared state across steps beyond what the server persists.
- Minimal styling — system fonts, no custom icon fonts.

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
