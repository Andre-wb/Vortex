# `vortex_controller/web/assets/` — Controller Site CSS + JS

CSS + JS assets served at `/static/*` by the controller site.

Typical layout:

```
assets/
├── css/
│   ├── theme.css           ← palette tokens
│   ├── layout.css          ← shell layout (header, nav, page body)
│   └── page-<name>.css     ← one stylesheet per page
├── js/
│   ├── controller.js       ← shared helpers + signed-response verification
│   ├── page-<name>.js      ← per-page behaviour (nodes table, admin dashboard, etc.)
│   └── sig.js              ← Ed25519 signature verification (vanilla WebCrypto + small helper)
└── img/                    ← static imagery referenced by pages
```

## Signed-response verification

`sig.js` verifies every `/v1/*` response against the controller's pubkey pinned at build time. Pages **must** call `controller.fetchSigned(url)` instead of raw `fetch()` — an unsigned or wrong-signature response is rejected before it reaches the renderer, so a hostile MITM can't spoof node URLs.

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
