# `app/utilites/` — Pure Utility Helpers

Miscellaneous helper functions with no external dependencies. Deterministic, side-effect-free, unit-tested.

> The folder name is spelled `utilites` (missing `i`). This is intentional — renaming would break every import. A fresh project would pick `utils/`; this one keeps the original typo to avoid a footgun migration.

## Files

| File        | Role                                                                               |
| ----------- | ---------------------------------------------------------------------------------- |
| `utils.py`  | Catch-all helpers — string shaping, time formatting, byte-size formatters, safe JSON round-trip, ID generation, batch chunking, random token mint, async-retry decorator. |

## What belongs here

Anything that is:

- **Pure**: given the same input, returns the same output. No I/O, no global state mutation.
- **Widely reusable**: needed from 3+ feature packages.
- **Cheap**: a few lines, no external deps.

## What doesn't

- Anything that talks to the DB — goes in the feature package that owns the model.
- Crypto — goes in `../security/crypto.py`.
- HTTP clients — goes next to the feature that uses them.
- Anything with per-request state — goes in the request scope, not a module-level helper.

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
