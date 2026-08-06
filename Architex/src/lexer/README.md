# `Architex/src/lexer/` — Tokeniser

Turns `.arx` source text into a flat token stream. Zero dependencies, one pass, no lookahead beyond a single character.

## Responsibilities

- Recognise keywords: `@screen`, `@component`, `@state`, `@effect`, `col`, `row`, `stack`, `text`, `input`, …
- Recognise modifiers after `::` — `pad(n)`, `gap(n)`, `radius(n)`, `bold`, `center`, `color(#...)`, …
- String interpolation: `"Hello, {~name}!"` splits into `StringStart / Expr / StringEnd`.
- Indent / dedent tokens drive the off-side parser.
- Comments — `#` to end of line — are stripped before emission.
- Numbers (int + float), colours (`#RRGGBB` / `#RGB`), identifiers.

## Output shape

```ts
type Token =
  | { kind: "ident"; value: string; pos: Pos }
  | { kind: "number"; value: number; pos: Pos }
  | { kind: "string_start"; pos: Pos }
  | { kind: "string_part"; value: string; pos: Pos }
  | { kind: "string_expr_open"; pos: Pos }
  | { kind: "string_expr_close"; pos: Pos }
  | { kind: "string_end"; pos: Pos }
  | { kind: "punct"; value: string; pos: Pos }     // ::, =, ~, @, (, ), ,
  | { kind: "indent"; level: number; pos: Pos }
  | { kind: "dedent"; level: number; pos: Pos }
  | { kind: "eof"; pos: Pos };
```

## Errors

Lexer errors are recoverable — an invalid character yields an `InvalidToken` and the lexer skips ahead. The parser decides whether this is fatal.

## Testing

Unit tests live in `__tests__/lexer.test.ts`. Snapshot-based: a fixture `.arx` file vs. its expected token stream.

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
