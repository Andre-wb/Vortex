# `node_setup/static/js/` — First-run Wizard JS

Minimal JavaScript for the server-side first-run wizard. One file per step validator + shared helpers.

Typical modules: `setup.js` (form submit glue), `ssl.js` (SSL-step specifics, ACME progress polling), `peer.js` (controller pubkey validation), `progress.js` (SSE connector for long-running steps).

## Conventions

- Vanilla JS, no framework.
- Plain `fetch` calls — no extra HTTP wrapper.
- Fail gracefully: the wizard stays usable as a pure HTML form when JS is disabled.

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
