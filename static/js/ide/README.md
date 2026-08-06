# `static/js/ide/` — In-browser IDE

The Gravitix + Architex editor hosted at `/ide`. Vanilla JS, no framework, no bundler.

## Modules

- `editor.js` — core text editor (CodeMirror 6 style behaviour, written from scratch): line numbers, caret, selection, Undo/Redo, soft-wrap, find/replace.
- `highlight.js` — syntax highlighter shared by Gravitix and Architex (pluggable grammars).
- `completion.js` — autocomplete: stdlib, local identifiers, modifier names for Architex.
- `lint.js` — inline diagnostics from parse errors and budget warnings.
- `runner.js` — runs the current project via `POST /api/bots/ide/run` (Gravitix) or mounts in a sandboxed iframe (Architex).
- `preview.js` — live preview pane for Architex.
- `monitor.js` — log tail + stack samples for running bots.
- `projects.js` — project explorer, create / rename / delete / publish.
- `console.js` — REPL-like evaluator for quick language experiments.
- `dev_settings.js` — dev-only knobs (hot reload, raw AST dump, token dump).

## Loaded from

`../../templates/screens/ide.html` — which loads `ide/*.js` in declared order before calling `IDE.init(rootElement)`.

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
