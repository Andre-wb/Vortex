# `src-tauri/` — Tauri Desktop Shell

Native desktop wrapper for the Vortex web client. Uses [Tauri v5](https://tauri.app/) — the app boots a real browser engine (WKWebView on macOS, WebView2 on Windows, WebKitGTK on Linux) and points it at either the bundled static UI or a running Vortex node.

Minimal on purpose — the heavy lifting (auth, crypto, networking) happens in the JavaScript front-end. Tauri only provides the window, menu bar, file-system shims, and native notifications.

## Files

| Path              | Role                                                                                          |
| ----------------- | --------------------------------------------------------------------------------------------- |
| `Cargo.toml`      | Rust dependencies — Tauri runtime, any custom commands.                                       |
| `build.rs`        | Tauri's build script. Runs during `cargo build` to embed the web assets and window metadata.  |
| `tauri.conf.json` | App identity, window size, allowlist (which Tauri APIs the front-end can call), updater URL. |
| `src/main.rs`     | Entry point. Registers custom `#[tauri::command]` handlers and starts the Tauri builder.      |
| `icons/`          | Platform icons — `.icns` (macOS), `.ico` (Windows), and PNG sizes for Linux.                  |

## Building

Requires Rust stable + the Tauri CLI:

```bash
cargo install tauri-cli --version '^2.0'
cd src-tauri
cargo tauri dev                # live-reload during development
cargo tauri build              # release bundle (.app / .msi / .deb / .AppImage)
```

On macOS the build produces `src-tauri/target/release/bundle/macos/Vortex.app`.

## What lives here vs. the wizard

| Concern            | Tauri shell (`src-tauri/`)                        | Wizard bundle (`vortex_wizard/`)                 |
| ------------------ | ------------------------------------------------- | ------------------------------------------------ |
| Bundles the node?  | No — connects to an already-running node.         | Yes — PyInstaller ships everything in one binary. |
| Language           | Rust (native) + JS front-end.                     | Python + pywebview + bundled Python runtime.      |
| Intended for       | Daily-driver chat UI.                             | First-run operator setup.                         |
| Auto-update        | Yes — Tauri updater pulls signed bundles.         | No — manual replace.                             |

The two are independent releases; either can ship without the other.

## Config notes

- `tauri.conf.json` sets `identifier: "com.vortex.chat"`, `version: "1.0.0"`, and points the dev URL at `http://localhost:5173/` (vite-served mirror of `static/` + `templates/`).
- The production build reads its UI from `../static/` + `../templates/` via Tauri's asset protocol; no file-system access outside that sandbox.
- The updater endpoint is disabled by default — set `plugins.updater.endpoints` before you ship.

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
