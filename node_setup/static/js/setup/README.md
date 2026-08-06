# `node_setup/static/js/setup/` — Setup Step Validators

Per-step JS validators for the server-side first-run wizard. Each module binds to its step's form and validates client-side before the POST, to give the operator immediate feedback.

- `network.js` — port range check, bind-address syntax.
- `identity.js` — seed checksum validation.
- `ssl.js` — ACME domain format, self-signed toggle visual feedback.
- `database.js` — DSN syntax + `/setup/db/test` probe on blur.
- `peer.js` — controller pubkey hex length.

Each is a plain `<script>` — no framework, no module system. Fails gracefully if JS is off.

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
