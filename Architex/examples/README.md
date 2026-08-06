# `Architex/examples/` — Example `.arx` Mini Apps

Reference apps showcasing each Architex language feature. Every file is runnable via the Vortex IDE's preview pane — paste into the IDE, hit Run.

## Files

| File                    | Demonstrates                                                     |
| ----------------------- | ---------------------------------------------------------------- |
| `counter.arx`           | The canonical Hello-world — `~count` signal + increment button.  |
| `todo.arx`              | List state, add / remove / toggle, `computed` for the footer count. |
| `form.arx`              | Multi-field form, `~valid` computed, submit handler.             |
| `router.arx`            | Nested `@screen`s routed by `~route` signal. Demonstrates conditional mounts. |
| `components.arx`        | Defines + uses `@component Card(title, body)`.                   |
| `theme.arx`             | Theming via CSS custom-property bindings.                         |
| `modifiers.arx`         | Every built-in modifier — `pad`, `gap`, `radius`, `bold`, `center`, `color`, `border`. |
| `list.arx`              | Virtualised list using the `each` primitive.                     |
| `effect.arx`            | `@effect` with cleanup — a setInterval that tears down on unmount. |
| `interpolation.arx`     | String interpolation, nested signals, computed helpers.           |

## Running

```bash
# Inside the Vortex IDE
1. Open the IDE (web client → "/ide")
2. New project → "Architex"
3. Paste a .arx example into the editor
4. Click Run
```

Or headlessly via the Node-side compiler:

```bash
cd Architex
npm test -- examples/counter.arx       # lexer + parser + runtime smoke
```

## Contributing examples

- Keep each example small — one concept per file.
- Prefer built-in modifiers over custom components unless the example is *about* components.
- Comment sparingly — the code should explain itself. A one-line `# …` header per file is fine.

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
