# `Gravitix/static/` — Static Assets for the Gravitix Demo Site

Assets used by the standalone Gravitix demo site (see `../run.py`). The main Vortex web client does NOT consume these — it has its own assets under `../../static/`.

## What's here

- `index.html` shell + supporting CSS + JS for a minimal "try Gravitix in the browser" page.
- Syntax-highlighter styles for the `.grv` grammar.
- A tiny WASM-compiled lexer/parser slice, if present, so the page can preview code without a server round-trip.

## Running the demo site

```bash
cd Gravitix
python run.py                  # serves on http://localhost:7787/
```

Useful when hacking on Gravitix itself without booting the full Vortex backend.

## Keep separate

- **Do not** copy these files into the main site — the main client has different styling tokens and a different layout.
- If you want to share snippet highlighters across Vortex and Gravitix, factor them into `../src/` and expose via the CLI / WASM build; don't duplicate CSS.

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
