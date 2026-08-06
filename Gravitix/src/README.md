# `Gravitix/src/` — Gravitix Runtime (Rust)

Rust implementation of the Gravitix bot language. ~12.5K lines, 96 language features, 165 tests passing, zero runtime deps beyond the Rust stdlib + a tiny serde for JSON I/O.

## Pipeline

```
.grv source
   │
   ▼
lexer       ← tokeniser (flat file at src level)
   │
   ▼
parser      ← recursive descent (flat file at src level)
   │
   ▼
interpreter/ ← AST-walking evaluator, handlers, flows
   │
   ▼
bot/        ← runtime integration — ctx, emit, schedule, state store
   │
   ▼
stdlib/     ← safe built-ins available from user code
```

## Top-level files (selected)

| File               | Role                                                              |
| ------------------ | ----------------------------------------------------------------- |
| `lib.rs`           | Crate root; re-exports the public API.                            |
| `lexer.rs`         | Single-pass tokeniser.                                             |
| `parser.rs`        | Recursive-descent parser; produces `Ast`.                          |
| `ast.rs`           | AST node definitions.                                              |
| `types.rs`         | Runtime value types (Number, String, Bool, List, Map, Closure, …).|
| `errors.rs`        | Error enum with positions.                                         |
| `main.rs` (bin)    | CLI entry — `gravitix run <file>`, `gravitix check <file>`.       |

## Sub-modules

### `interpreter/`

AST-walking evaluator, flow control, event handlers, pattern matching, guards, pipe operator, lambdas, structs, FSM.

### `bot/`

Runtime integration — the `ctx` object (message, user, args), `emit` (send back), `schedule` (cron-like), `state` (persistent KV per bot + per user), command registration, slash-command parser.

### `stdlib/`

Pure-function standard library — math (`abs`, `floor`, `sin`, `cos`, `sqrt`, …), strings (`upper`, `lower`, `split`, `replace`, `regex_match`), lists (`map`, `filter`, `reduce`, `len`, `sort`), maps, time, JSON encode/decode, base64, UUID, stats (`mean`, `stddev`), date formatting, number formatting.

**Not in stdlib** (intentionally blocked): file I/O, direct HTTP, process spawn, shell, arbitrary `eval`. HTTP goes through a gated, allow-listed client exposed via `bot/`.

## Testing

```bash
cd Gravitix
cargo test                   # 165 tests
cargo test -- --nocapture    # see println! output
cargo bench                  # lexer + parser + interp benches (optional)
```

## Binary

`cargo build --release` produces `target/release/gravitix` — a CLI you can run outside Vortex:

```bash
gravitix run my_bot.grv
gravitix check my_bot.grv    # lint only, no run
gravitix repl                # interactive
```

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
