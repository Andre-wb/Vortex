# `vortex-test/public/` — Test Harness Static Site

Static assets for the standalone Vortex test harness. `vortex-test/` is a trimmed-down site used for automated browser tests (Playwright) and for demoing specific flows in isolation without booting the full web client.

## Layout

```
public/
├── index.html         ← minimal shell
├── assets/            ← per-scenario CSS + JS
├── icons/             ← tiny icon set
└── locales/           ← trimmed locale JSON (scenario-specific copies)
```

## Usage

```bash
cd vortex-test
python -m http.server 5555
# open http://localhost:5555/
```

## When to use

- You want a Playwright test that exercises a specific flow (e.g. just the auth UI) without loading the full 65-JS-module main client.
- You're reproducing a bug that requires a minimal page with known-good fixtures.
- You're iterating on a single component without the rest of the app in the way.

## When NOT to use

- Anything customer-facing — use `../../static/` + `../../templates/` instead.
- Integration tests that span multiple features — use the full app.

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
