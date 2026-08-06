# `static/sounds/` — Notification / UI Sounds

Short audio clips for notifications, calls, and UI feedback.

## Files (typical)

- `notification.ogg` / `.mp3` — new-message sound.
- `mention.ogg` — direct-mention sound.
- `call-ringing.ogg` — outgoing call loop.
- `call-incoming.ogg` — incoming call loop.
- `call-end.ogg` — call-end short.
- `join.ogg`, `leave.ogg` — voice-room affordances.
- `error.ogg` — error toast.

Both `.ogg` and `.mp3` variants ship — browsers pick whichever they can decode.

## Conventions

- All clips ≤ 2 seconds except the ringing loops.
- Normalised to −16 LUFS so no clip is noticeably louder than the others.
- Safe-for-work; no voice.
- Every clip is license-cleared for redistribution (CC0 / CC-BY source, noted in the commit message when added).

## Loading

Sounds are loaded by `../../js/notification-sounds.js` and played through an `AudioContext` with per-kind volume settings exposed in user settings.

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
