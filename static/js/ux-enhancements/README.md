# `static/js/ux-enhancements/` — Optional UX Polish Modules

Modules that improve the feel of the app but are not required for core functionality. Every one is lazy-loaded and fails gracefully — the site works identically if a module fails to load.

## Typical modules

- `skeleton.js` — skeleton placeholders while data loads.
- `ripple.js` — Material-style ripple effect on buttons.
- `haptics.js` — vibration API wrapper (mobile browsers).
- `scroll_memory.js` — remembers scroll position per room / per page.
- `shortcuts.js` — global keyboard shortcuts + help overlay.
- `anim.js` — shared easing presets for micro-interactions.
- `toast.js` — corner-toast notifications.
- `progressive_blur.js` — animated background blur on scroll.

## Conventions

- Every module exports `install(rootElement)` and does nothing if its prerequisites (e.g. `navigator.vibrate`) aren't available.
- Failing to load a single module **must not** cascade — the site's main bundle never imports from here synchronously.

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
