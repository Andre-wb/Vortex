# `logo/` — Vortex Brand Assets

Primary brand logo in multiple formats + sizes. Consumed by web UI, wizard, Tauri shell, README banners.

## Files

Expected set:

- `logo.svg` — canonical vector source.
- `logo.png` (master 1024×1024).
- `logo-<size>.png` for common UI sizes (16, 32, 64, 128, 256, 512).
- `wordmark.svg` — horizontal logotype.
- `icon-mono.svg` — single-colour mask, tintable.
- `favicon.ico`.

## Usage

- Web UI picks `icon-mono.svg` and tints via CSS `mask-image`.
- Wizard bundle embeds `logo.png` in the `Vortex Wizard.app` bundle.
- Tauri reads platform-specific icons from `src-tauri/icons/` — do not move master assets there; keep them here and regenerate derivatives.

## Licensing

Brand assets are proprietary to Vortex — same AGPL-3.0-or-later licence as the code, but the logo itself is NOT a trademark-free grant. Don't ship a fork using the Vortex logo unless you're shipping Vortex.

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
