# `static/js/vendor/` — Vendored Third-party Libraries (JS)

Full third-party JavaScript libraries vendored at a specific version. Distinct from `../lib/` (which holds small shims + polyfills) — this folder is for complete, license-preserved copies of external code.

## Conventions

- Every vendored library lives in its own subfolder.
- Each subfolder keeps the original `LICENSE` file alongside the JS.
- Every file carries a top comment stating `// Source: <URL>, version <X>, vendored <YYYY-MM-DD>`.
- No modifications. If a bug needs fixing, vendor the patched upstream tag; never edit in place.

## Upgrading

1. Download the new release into a sibling folder `_pending/`.
2. Run the smoke tests (Playwright + Jest) to make sure nothing broke.
3. Swap folders; update the top-comment vendored date.
4. Commit in one step.

## Why vendored

- Reproducible builds without npm / CDN dependency.
- CSP compatibility — every script lives at a known path on our origin.
- Survives third-party outages.

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
