# `static/js/rooms/` — Rooms-UI Modules

Per-concern rooms UI. Attaches to `window.Rooms.<Namespace>`.

## Modules

- `list.js` — the left-side rooms list (pins, unread counters, drag-to-reorder).
- `create.js` — create-room wizard integration (the modal itself is in `../../../templates/modals/create_room.html`).
- `members.js` — member panel: list, add, remove, change role.
- `permissions.js` — per-role permission matrix editor.
- `theme.js` — room theme editor (background, accent, icon tint).
- `keys.js` — key-rotation UI, fingerprint verification, pending-delivery indicator.
- `invite.js` — invite-code + link generator, QR.
- `forum.js` — forum-topics layout for rooms in forum mode.

Used by `../../../templates/screens/chat.html` and `room_settings.html`.

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
