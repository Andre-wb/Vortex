# `static/js/chat/messages/` — Message Renderer Submodules

Per-kind renderers for the chat message list. One file per message kind so the renderer dispatcher in `../renderer.js` can lazy-load kinds on demand.

## Typical files

- `text.js` — plain text with link + emoji parsing.
- `image.js` — image bubble with tap-to-open-gallery.
- `video.js`, `audio.js` — media players.
- `file.js` — file attachment card.
- `poll.js` — poll renderer with vote state.
- `card.js` — generic rich card (title + body + buttons + image).
- `miniapp.js` — embedded Architex Mini App renderer.
- `system.js` — server-issued system messages (joined, left, renamed).
- `fallback.js` — "unknown kind" tile with raw hex dump.

## Conventions

- Every renderer exports `render(messageDOM, payload)` and `teardown(messageDOM)`.
- No cross-file imports — talk to `../bus`.

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
