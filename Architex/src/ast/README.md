# `Architex/src/ast/` — AST Types & Walker

Typed AST nodes for an Architex program + a visitor-pattern walker. No evaluation logic — the runtime lives in `../runtime/`.

## Node kinds

```ts
type Node =
  | File           // root — a parsed .arx file
  | Screen         // @screen Name
  | Component      // @component Name(params)
  | StateDecl      // ~foo = expr
  | EffectDecl     // @effect ...
  | Element        // col / row / text / … + modifiers + children
  | Modifier       // pad(8), bold, color(#fff)
  | Expr           // literal, ident, call, interpolation
  | …
```

## Walker

```ts
interface Visitor<T> {
  visitScreen?(node: Screen, ctx: T): void;
  visitComponent?(node: Component, ctx: T): void;
  visitElement?(node: Element, ctx: T): void;
  visitExpr?(node: Expr, ctx: T): void;
  …
}

walk<T>(root: File, visitor: Visitor<T>, ctx: T): void;
```

The walker is depth-first pre-order. Visitors can return `false` from any hook to skip descent.

## Why a separate folder

- The runtime's evaluator is ~600 lines. Keeping AST types next to it would bloat imports for tests and tools (linters, formatters) that only need the shape.
- Any future visualiser / printer / formatter lives here too.

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
