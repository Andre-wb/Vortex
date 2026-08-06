# `docs/` — Human-written Documentation

Hand-written Markdown files that don't fit the generated locale-driven docs site. Intended for developers working in a shell, not end users.

For the navigable multi-root docs portal (Vortex / Gravitix / Architex with accordions) see [`../vortex-introduce-page/docs.html`](../../vortex-introduce-page/docs.html).

## Files

| File                  | Audience                 | What's inside                                                                           |
| --------------------- | ------------------------ | --------------------------------------------------------------------------------------- |
| `QUICKSTART.md`       | New operator             | Install → first boot → first message in ~5 minutes. Bare-metal path, no Docker.         |
| `API_REFERENCE.md`    | Third-party integrator   | Flat API reference. The authoritative copy is the generated `apiSurface` in the locale JSON, but this file is kept for users who want a single Markdown page. |
| `BOT_DEVELOPMENT.md`  | Bot author               | End-to-end Gravitix walkthrough: install CLI → first handler → publish to marketplace. Cross-references the full Gravitix reference at `../Gravitix/README.md`. |
| `adr/`                | Core developer, reviewer | Architecture Decision Records. `001` — message-encryption protocol versioning (`enc_v` registry) and the Double Ratchet migration target. `002` — multi-device v2 (per-device Sesame) decision fork and proposal. `003` — asymmetric device→account binding (P1) design and feasibility verdict. |

## How these relate to the locale docs

- Locale JSON (`static/locales/*.json`) is the **canonical** doc source — it drives the iOS app, Android app, and `docs.html` simultaneously.
- Everything here in `docs/` is either:
  - a shortcut for terminal users (`QUICKSTART.md`), or
  - a living PR-reviewable copy of something that is otherwise hard to review in JSON form (`API_REFERENCE.md`, `BOT_DEVELOPMENT.md`).
- If the two ever disagree, **trust the locale JSON** — it's what clients actually render.

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
