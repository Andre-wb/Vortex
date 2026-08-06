# `Architex/src/runtime/` — Interpreter

Walks the `../ast/` tree, wires `../reactive/` primitives, and produces a live element tree that `../renderer/` can draw.

## Responsibilities

- Instantiate `signal()` for every `~name` declaration.
- Build a reactive element tree — a tree of objects that mirror the AST shape but whose text / attrs / children are `computed()` closures.
- Resolve identifier references (local signals → component params → enclosing scope).
- Evaluate expressions (literals, operators, function calls into the safe stdlib).
- Handle component instantiation — parameters, isolated scope, recursive mount.
- Handle `@effect` blocks — create an `effect()` that runs on mount, re-runs when dependencies change.

## Entry points

```ts
function mount(file: File, root: RendererRoot, scope?: Scope): Dispose;
function mountComponent(name: string, props: Record<string, any>, root: RendererRoot): Dispose;
```

Returns a `Dispose` function that tears down all effects, components, and DOM nodes.

## Safe stdlib

Expressions can call a curated subset:

- Maths: `min`, `max`, `abs`, `round`, `floor`, `ceil`.
- String: `upper`, `lower`, `trim`, `len`, `split`, `join`, `replace`.
- Array: `map`, `filter`, `sum`, `reverse`, `slice`.
- Time: `now()`.

Everything else is forbidden — no `eval`, no `fetch` from expressions (side-effects happen in `@effect` via injected scope helpers the host sets up explicitly).

## Isolation

Components get their own scope. Parent components can pass props in; children cannot read parent state except by prop. This keeps data flow explicit — good for bot-authored Mini Apps shipping over the wire.

## Testing

`__tests__/runtime.test.ts` — mount-test-dispose cycles, reactivity round-trips, scope isolation, component lifecycle.

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
