# `static/vendor/` — Vendored Third-party Static Assets

Non-JS third-party static assets (fonts, icon packs, external stylesheets) vendored at pinned versions. Distinct from `../js/vendor/` which holds JS libraries.

## What typically lives here

- `fonts/` — font families licensed for redistribution (see its README).
- `*.css` — vendored external stylesheets (e.g. a third-party icon font).
- `*.woff2` — direct font files if the font isn't under `fonts/`.

## Conventions

- Each vendored asset preserves its original license file next to it.
- Each folder's README names the source + version.
- No modifications — if you need custom tweaks, layer your overrides in `../css/`.

## Why vendored

Same reasons as `../js/vendor/`: reproducibility, CSP cleanliness, offline-safety, audit clarity.

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
