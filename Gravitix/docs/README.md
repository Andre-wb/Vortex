# `Gravitix/docs/` — Legacy Documentation

Older hand-written Markdown docs for Gravitix. The **canonical** documentation source today is the locale JSON under `../../static/locales/*.json` (keys `gravitixDocs.*`) rendered by the docs portal at `/docs.html`. This folder is kept for tooling that expects plain Markdown.

## Files

Typical contents (exact list in the directory):

- `syntax.md` — quick syntax reference.
- `stdlib.md` — list of built-in functions.
- `bot-guide.md` — first-bot walkthrough.
- `flows.md` — flow / FSM primer.
- `pattern-matching.md` — deep dive on `match` + guards.

## Relation to the locale docs

- Content here was migrated to the locale tree by `../../scripts/convert_gx_docs_i18n.py`.
- Further edits should go to the **English locale** (`static/locales/en.json`, `gravitixDocs.*`). The translate scripts propagate to the other 145 locales.
- If something in this folder disagrees with the locale tree, **trust the locale**.

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
