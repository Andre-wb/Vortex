# `static/js/lib/` — Vendored Third-party Shims

Small vendored third-party libraries. Kept here instead of via npm/CDN so the site keeps working without a package manager and without third-party uptime dependencies.

## Contents (typical)

- Tiny DOM utilities that pre-date modern browsers' built-ins.
- Crypto helper polyfills for older WebView environments.
- Small MIME / base58 / base64url helpers.

## Conventions

- **Every vendored file names its source + version** in the top comment.
- **No transitive dependencies.** If a library imports three others, we don't vendor it.
- **Never patch in-place.** If a bug needs fixing, keep the original + a sibling `<name>.patch.js` that monkeypatches on load. Makes audits easy.

## Why not npm

- Deterministic byte-for-byte builds across hosts without needing `node_modules`.
- No Supply-chain surface area — every file here was reviewed before commit.
- Site works fine with CSP'd no-eval / no-inline environments that would trip up modern bundler output.

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
