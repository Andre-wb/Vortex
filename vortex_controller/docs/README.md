# `vortex_controller/docs/` — Controller Operator Docs

Hand-written Markdown for controller operators. Shorter-lived than the user-facing docs site — specific to one role (running the controller service).

## Files

| File            | Audience               | Content                                                                                       |
| --------------- | ---------------------- | --------------------------------------------------------------------------------------------- |
| `DEPLOY.md`     | Operator               | Full deployment walkthrough: PostgreSQL setup, pubkey pinning, Tor onion, Cloudflare tunnel, systemd unit. |
| `INTEGRITY.md`  | Operator / security    | How the integrity manifest is built, signed, and verified; what `INTEGRITY_STRICT=1` enforces; how to rotate the integrity key. |
| `SOLANA.md`     | Operator               | How the controller cross-checks the on-chain `vortex_registry`; RPC selection; what to do when the program is upgraded. |

## Relation to the locale docs

Controller-specific docs don't have a home in the user-facing locale tree — they're operator-only. Kept here as Markdown so operators reading the repo find them next to the code.

If an operator doc ever becomes useful for end users, migrate the content into `static/locales/en.json` (`vortexDocs.*`) and delete the Markdown — avoid two sources of truth.

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
