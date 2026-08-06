# `Architex/src/` — Language Implementation

TypeScript source of the Architex runtime. Parses `.arx` files, builds a reactive AST, runs them against a pluggable renderer. Zero runtime dependencies; ships unbundled but tree-shakes under any modern bundler.

## Pipeline

```
.arx source
   │
   ▼
lexer/     ← tokenises the file; produces a flat token stream
   │
   ▼
parser/    ← builds the AST; enforces indentation rules
   │
   ▼
ast/       ← AST node definitions + walker helpers
   │
   ▼
reactive/  ← fine-grained reactive state (signals + effects)
   │
   ▼
runtime/   ← evaluates the AST against a reactive scope
   │
   ▼
renderer/  ← turns the reactive VDOM into HTML / native descriptors / diff
```

## Folders

| Path         | Role                                                                                   |
| ------------ | -------------------------------------------------------------------------------------- |
| `lexer/`     | Character → token. Handles string interpolation (`"Hello, {~name}"`), indent tokens, operators, modifiers. |
| `parser/`    | Token → AST. Indentation-driven (off-side rule). Produces typed AST nodes.            |
| `ast/`       | AST node interfaces and the walker. No evaluation logic.                               |
| `reactive/`  | Signals, computed, effects. A fine-grained reactive graph — only touched nodes re-render. |
| `runtime/`   | Interpreter. Walks the AST, constructs a reactive VDOM, wires effect subscriptions.    |
| `renderer/`  | Pluggable renderers — `html` (DOM), `native` (opaque view descriptors for iOS / Android), `diff` (headless, useful for tests + SSR). |

See each sub-README for details.

## Entry point

`../dist/architex-runtime.js` is the built shim used by the web client. The entry file is `index.ts` at this level (exports `parse`, `compile`, `renderTo`, `ReactiveScope`).

## Testing

```bash
cd Architex
npm test                       # jest against src/**/__tests__/
```

## Design principles

- **No build step** required to author `.arx` files. The runtime accepts source at boot.
- **Fine-grained reactivity** — no full-VDOM diffing; only the exact node that reads a signal re-renders when it changes.
- **Declarative** — everything about the UI is in the `.arx` file, including event handlers (as expression-level callbacks).
- **Three-layer separation** — lexer, parser, runtime are independent; renderer is pluggable. Swapping HTML → native requires no change above `renderer/`.

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
