# `static/js/chat/` — Chat-UI Modules

Per-concern chat-UI modules. Each attaches to `window.Chat.<Namespace>` via the loader in `../main.js`.

## Modules

- `composer.js` — message composer: text input, attachment bar (mic + file), scheduled-send picker, slash-command autocomplete.
- `renderer.js` — message bubble renderer — text, media, polls, cards, Architex Mini App embeds, fallback "unknown kind" tile.
- `reactions.js` — react / long-press menu, reaction picker, animated counters.
- `read_receipts.js` — "seen by N" pill under outgoing bubbles.
- `typing.js` — typing indicator over composer.
- `threads.js` — thread side panel + thread creation.
- `presence.js` — online / typing / read state from the shared presence channel.
- `scheduled.js` — scheduled-send queue UI.
- `voice.js` — voice-note player / recorder integration.

## Conventions

- Each module binds on `init(rootElement)` and unbinds on `teardown()` — the chat screen's owner calls both on route change.
- No direct DOM mutation outside the rooted element.
- No cross-module imports — communicate via `window.Chat.bus.emit/on`.

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
