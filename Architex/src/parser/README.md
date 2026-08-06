# `Architex/src/parser/` — Parser

Token stream → AST. Indentation-driven (off-side rule). Single pass, no backtracking.

## Responsibilities

- Consume the token stream from `../lexer/`.
- Produce `../ast/` node trees — one root per `@screen` / `@component` declaration.
- Enforce grammar (arity of modifiers, shape of declarations).
- Track source positions so errors point at the right line.

## Grammar sketch

```
File         := Declaration+ EOF
Declaration  := Screen | Component
Screen       := "@screen" Ident Indent Body Dedent
Component    := "@component" Ident "(" Param* ")" Indent Body Dedent
Body         := (StateDecl | EffectDecl | Element)+
StateDecl    := "~" Ident "=" Expr
EffectDecl   := "@effect" Indent Expr Dedent
Element      := Tag ModifierList? Indent Body? Dedent
Tag          := Ident | Ident "(" Args ")"
ModifierList := "::" Modifier (Modifier)*
Modifier     := Ident ("(" Args ")")?
```

## Error recovery

On an unexpected token the parser:

1. Emits a `ParseError` with position.
2. Skips to the next dedent (to stay synchronised with indentation).
3. Continues — so one broken screen doesn't kill the whole file.

Errors bubble up to the runtime, which renders an in-page red overlay during development.

## Output

Single entry point: `parse(tokens: Token[]): File`. Returns the AST root or throws if the token stream is unrecoverable.

## Testing

`__tests__/parser.test.ts` — golden AST snapshots for a curated set of `.arx` fixtures.

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
