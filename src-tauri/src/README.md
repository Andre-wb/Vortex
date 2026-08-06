# `src-tauri/src/` — Tauri Rust Source

Rust source for the desktop shell. Minimal — Tauri handles the heavy lifting; this code only sets up the window, registers custom commands (if any), and launches the event loop.

## Files

| File      | Role                                                                                |
| --------- | ----------------------------------------------------------------------------------- |
| `main.rs` | Entry point. Builds the Tauri app, registers any `#[tauri::command]` handlers, starts the event loop. |

## Typical shape

```rust
fn main() {
    tauri::Builder::default()
        .setup(|app| { /* optional custom init */ Ok(()) })
        .invoke_handler(tauri::generate_handler![/* commands */])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

## Commands

Currently none — the front-end talks to Vortex over HTTP/WebSocket directly. If a future feature needs privileged filesystem / OS access (e.g. clipboard history, native notifications with custom actions), add a `#[tauri::command]` here and whitelist it in `../tauri.conf.json`.

## Building

See [`../README.md`](../README.md).

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
