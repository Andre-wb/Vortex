# `vortex_wizard/web/assets/` — Wizard UI Assets

CSS + JS + images for the desktop wizard UI. Shared across `../setup/` and `../admin/` pages.

## Layout

```
assets/
├── css/
│   ├── theme.css          ← wizard palette tokens (brighter than main app)
│   ├── layout.css         ← window, header, footer, content area
│   └── page-*.css         ← per-page styling
├── js/
│   ├── api.js             ← fetch wrapper with bearer token + error shape
│   ├── ui.js              ← toast, modal, progress widget, SSE helper
│   ├── i18n.js            ← loads locale JSON from ../locales/
│   └── page-*.js          ← per-page behaviour
└── img/                   ← brand imagery, setup illustrations
```

## Conventions

- No framework.
- No bundler — plain scripts, loaded in order by each HTML shell.
- Every script is feature-detected; pages still render if JS fails.

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
