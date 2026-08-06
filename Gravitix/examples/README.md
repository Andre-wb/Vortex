# `Gravitix/examples/` — Example `.grv` Bots

Reference bots showcasing every Gravitix feature. Each file is runnable via the `gravitix` CLI or via the in-browser IDE.

## Running

```bash
cd Gravitix
cargo run --release -- run examples/hello.grv
# or via the IDE in the Vortex web client
```

## Selected examples

| File                    | Teaches                                                  |
| ----------------------- | -------------------------------------------------------- |
| `hello.grv`             | The canonical `on /start { emit "Hello!" }`.            |
| `todo_list.grv`         | Persistent state across invocations.                    |
| `todo_fsm.grv`          | FSM / flows for multi-step conversations.               |
| `poll_bot.grv`          | Poll composer with per-user vote tracking.              |
| `weather.grv`           | Allow-listed HTTP fetch + response card.                |
| `moderator.grv`         | `on join / on message` event handlers + pattern-matched ban triggers. |
| `scheduler.grv`         | `on schedule("0 9 * * *")` daily digest.                |
| `math_stats.grv`        | Demonstrates `math_stats.*` stdlib usage.                |
| `pipe.grv`              | Pipe operator and lambdas.                              |
| `match.grv`             | Pattern matching and guards.                            |
| `miniapp.grv`           | `emit screen "MyApp"` — hands off to an Architex Mini App. |

## Conventions

- One concept per file.
- Start each file with a one-line comment: `# Demonstrates: <concept>`.
- No external secrets. Examples use obviously fake endpoints / keys.

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
