# `vortex_wizard/web/` — Wizard UI Assets

Vanilla JS + HTML + CSS served by the local FastAPI instance in the wizard bundle. Every file here is inlined into the PyInstaller bundle and served at startup over `http://127.0.0.1:<random-port>`; pywebview points its embedded browser at that URL.

## Layout

```
web/
├── index.html            ← shell
├── <page>.html           ← one per wizard page
├── assets/
│   ├── css/              ← styles
│   ├── js/               ← behaviour
│   ├── icons/            ← SVGs
│   └── img/              ← static brand imagery
└── locales/              ← wizard UI strings
```

## Pages (shells)

| File                    | Wizard step                                          |
| ----------------------- | ---------------------------------------------------- |
| `index.html`            | Welcome / pick fresh-install vs. recover-from-backup.|
| `setup.html`            | Main setup wizard shell.                             |
| `identity.html`         | Generate / paste seed.                               |
| `ssl.html`              | Pick SSL path (self-signed / ACME / import).         |
| `database.html`         | Pick DB backend + test connection.                   |
| `mirrors.html`          | Configure mirror URLs and controller pubkey.         |
| `security.html`         | BMP, stealth, Tor, WAF toggles.                      |
| `finalize.html`         | Review + write config + launch node.                 |
| `operator/*.html`       | Post-setup operator dashboard — settings, logs, backup, monitoring, diagnostics. |

(File list approximate — check the directory listing for the exact shipped set.)

## JS organisation

- One module per page (`assets/js/setup.js`, `assets/js/operator.js`, …).
- Shared modules — `api.js` (wraps `fetch` with bearer token + error shape), `i18n.js`, `ui.js` (toast, modal, progress widget), `sw.js` (service worker for offline refresh).

## i18n

The wizard ships a smaller locale set than the main app — operator-focused strings only, not the full user-facing UI. Files under `locales/` mirror the main-app structure: `en.json` is canonical, others fall back to English for missing keys.

## Styling

- Uses its own palette (slightly brighter than the main app) so operators don't confuse the wizard with the chat UI.
- `assets/css/theme.css` defines the tokens; per-page sheets consume them.
- No framework, no build step.

## Loaded by the bundle

PyInstaller's `vortex-wizard.spec` includes `vortex_wizard/web/` verbatim. The `server.py` FastAPI instance mounts this directory as static and registers per-page route handlers that return the HTML.

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
