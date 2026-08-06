# `static/js/ide-docs/` — IDE Docs Browser

Mini docs browser embedded inside the IDE. Same locale JSON source as `/docs.html` (`../../locales/`), but rendered in the IDE's side panel so users can learn the language without leaving the editor.

## Modules

- `renderer.js` — accordion renderer (the `hN / hN_a / hN_b / hN_c / hN_f` scheme).
- `search.js` — in-tree text search across the active root.
- `nav.js` — tree sidebar + route sync with the editor (hover a Gravitix keyword → auto-scroll to its reference entry).
- `bridge.js` — thin bridge between the editor and the docs panel (click a symbol → open its entry; drag a code sample → insert into the editor).

## Relation to `../../../vortex-introduce-page/docs.js`

This folder is a **subset** — it only renders the accordion chapter content and side navigation. It does not ship the home-page wrapping, locale picker, or marketing chrome. Both readers consume the same locale JSON and the same `hN / hN_a / hN_b / hN_c / hN_f` convention, so content stays in sync.

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
