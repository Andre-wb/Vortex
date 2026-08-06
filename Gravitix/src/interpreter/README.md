# `Gravitix/src/interpreter/` — AST Evaluator

AST-walking interpreter. Takes an `Ast` from the parser and evaluates it against a mutable `Environment`.

## Responsibilities

- Walk every AST node; produce a `Value`.
- Maintain lexical scope (let-bindings, closures, parameter shadowing).
- Run `on /command` handlers when dispatched by `../bot/`.
- Evaluate flow control — `if`, `match` with patterns + guards, `for`, `while`, `loop`, `break`, `continue`.
- Evaluate pipe operator `|>`, lambdas, pattern destructuring.
- Dispatch to `../stdlib/` for built-ins and to `../bot/` for runtime-backed functions.

## Hot path

The evaluator is designed to be cheap in the common bot case:

- **Single dispatch** — no dynamic dispatch table, match on `AstNode` variants.
- **Arena scope** — variables are slots in a `Vec<Value>` indexed at parse time; no hash lookups in hot code.
- **Tail calls** become loops at the interpreter level (explicit handling for simple cases).

## Sandboxing hooks

Every evaluator call is checked against:

- `instruction_budget` — hard cap on AST nodes evaluated per handler run.
- `wall_time_budget` — handler is killed if evaluation takes too long.
- `max_heap` — list / map growth beyond this aborts the handler.

Budgets come from `../bot/` configuration; the interpreter itself doesn't know about users or tenants.

## Testing

Interpreter-focused tests live in `../../tests/interpreter_*.rs`:

- `interpreter_control_flow.rs` — if / match / for / while / loop / break / continue.
- `interpreter_closures.rs` — capture semantics, partial application.
- `interpreter_patterns.rs` — pattern matching + guards.
- `interpreter_errors.rs` — error propagation, recovery, positions.

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
