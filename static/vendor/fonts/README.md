# `static/vendor/fonts/` — Vendored Web Fonts

Web fonts served to the browser. Every font here is licensed for redistribution.

## Formats

- `.woff2` — preferred (Brotli-compressed, universally supported).
- `.woff` — fallback for older browsers where present.

## Conventions

- One folder per family: `fonts/<family-name>/`.
- Each family folder carries its upstream `LICENSE` file.
- `@font-face` declarations live in `../../css/layout.css` — all `src: url("../vendor/fonts/...")`.

## Constraints

- **No webfonts from third-party CDNs at runtime.** Everything is first-party. Simpler CSP, no privacy surprise.
- **No webfonts that contain personally-identifying glyph variants** that could fingerprint users beyond standard Unicode ranges.
- **Subsetted** where feasible — Latin + Cyrillic basic + the handful of CJK codepoints we actually use in the UI chrome. Body text relies on system fonts in CJK locales to avoid a giant blocking payload.

## Adding a family

1. Drop the `.woff2` + original `LICENSE` into a new subfolder.
2. Add the `@font-face` in `../../css/layout.css`.
3. Reference the family via the `--font-*` custom properties.
4. Run Playwright — every screen must still render on browsers without font-loading (disable network requests in DevTools).

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
