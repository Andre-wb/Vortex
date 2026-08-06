# `static/logo/` — Brand Logo (served from `/static/logo/*`)

Runtime-served copies of the brand logo. Originals / masters live in `../../logo/` (repo root); this folder is a lightweight mirror so the web server doesn't have to reach outside `static/` at runtime.

## Contents

- `logo.svg`
- `logo.png` at common sizes (64, 128, 256, 512).
- `wordmark.svg`.

## Keeping in sync

If you add or update a size in `../../logo/`, mirror it here. The masters live outside `static/` so that server-side tools (Tauri bundle, iOS / Android asset pipeline, README badge assets) can read them without dragging the whole `static/` tree.

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
