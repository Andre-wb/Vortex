# `static/js/__tests__/` — JavaScript Unit Tests

Jest suites for the vanilla-JS modules under `../`. Runs headless; no browser needed.

## Running

```bash
cd /Users/borismaltsev/RustroverProjects/Vortex
jest                          # all JS tests
jest static/js/__tests__/crypto.test.js
jest --watch                  # TDD loop
```

Config lives at the repo root (`jest.config.js`, `babel.config.js`) — only ES2022 syntax support, no JSX, no React.

## Coverage

The suite covers the modules with non-trivial logic: `crypto.js`, `bmp-client.js`, `bmp-envelope.js`, `i18n.js`, `architex-runtime.js`, and their submodules. Pure-presentation modules (theme.css-adjacent glue) are not covered here — Playwright catches those end-to-end.

## Conventions

- Each test file is named `<module>.test.js`.
- One `describe` per module; one `it` per behaviour.
- Never import from the DOM — modules that touch `document` are tested via `jsdom`, loaded automatically by `jest.config.js`.

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
