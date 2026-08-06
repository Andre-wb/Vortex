# `static/elements/` — Inline SVG Icons

Inline SVG icons used by the web UI and the Liquid Glass PRO renderer. Kept as raw SVG files so we can either:

1. Inline them directly into markup via `{% include "../static/elements/<name>.svg" %}`, or
2. Embed them as CSS `mask-image:` for tintable icons.

## Files (selected)

| File                                  | Used in                                |
| ------------------------------------- | -------------------------------------- |
| `alert-sign-svgrepo-com.svg`          | Warnings, destructive confirm modals.  |
| `color-picker-svgrepo-com.svg`        | Room theme editor.                     |
| `delete-2-svgrepo-com.svg`            | Destructive actions.                   |
| `edit-svgrepo-com.svg`                | Inline edit affordances.               |
| `jellyfish-svgrepo-com.svg`           | Empty-state illustration.              |
| `player-pause-svgrepo-com.svg` / `player-play-svgrepo-com.svg` | Voice note + video player. |
| `reply-svgrepo-com.svg`               | Reply affordance in the chat composer. |
| `shark-danger-predator-angry-svgrepo-com.svg` | Anti-spam / moderation empty-state. |

## Conventions

- One file per icon. No sprite sheet — we rely on HTTP/2 multiplexing.
- All icons are authored at 24×24, with a `viewBox="0 0 24 24"`. Any size scaling happens via CSS.
- `fill="currentColor"` — every icon inherits the parent text colour unless explicitly overridden.
- No stroke icons; filled shapes only, to render cleanly at very small sizes.

## Licensing

Third-party icons are from [svgrepo.com](https://www.svgrepo.com/) under its permissive license. File stems preserve the `-svgrepo-com` suffix so their provenance stays traceable.

## Adding an icon

1. Drop the `.svg` here with a `kebab-case` name.
2. Prefer filled 24×24 with `fill="currentColor"`.
3. Reference it from markup or CSS; if it appears in more than one place, add it to a component template so all usages stay in sync.

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
