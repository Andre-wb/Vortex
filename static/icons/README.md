# `static/icons/` — PWA / Browser Icons

Icons referenced by `../manifest.json` and the HTML `<link rel="icon">` / Apple touch-icon chain.

## Files

Typical set (adjust to the actual directory listing):

- `icon-192.png`, `icon-512.png` — required PWA sizes.
- `icon-192-maskable.png`, `icon-512-maskable.png` — Android maskable icons (bleed into safe zone).
- `apple-touch-icon.png` — iOS home-screen (180×180).
- `favicon-32.png`, `favicon-16.png` — desktop browsers.
- `badge.png` — notification badge.

## Regenerating

Icons derive from `../logo/logo.png` (1024×1024 master). Any image-resize tool works:

```bash
# macOS / ImageMagick
magick static/logo/logo.png -resize 192x192 static/icons/icon-192.png
magick static/logo/logo.png -resize 512x512 static/icons/icon-512.png
```

## Constraints

- PNGs only (`manifest.json` requires PNG for installability).
- Maskable icons must have the safe-zone padding so Android's circle/squircle clipping doesn't eat content.
- Apple touch icon must be 180×180 and without alpha.

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
