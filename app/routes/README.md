# `app/routes/` — Top-level WebSocket Router

Top-level shared routes that don't belong to a specific feature package. Currently just one thing: the shared WebSocket entry that multiplexes every real-time channel.

## Files

| File            | Role                                                                                  |
| --------------- | ------------------------------------------------------------------------------------- |
| `websocket.py`  | Single WS endpoint at `/ws/chat/{room_id}` (and siblings `/ws/signal/*`, `/ws/stream/*`, `/ws/voice-signal/*`, `/ws/sfu/*`, `/ws/notifications`). Authenticates via JWT in the first frame, fans out to per-feature handlers, handles ping/pong, backpressure, graceful close. |

## Why one place

- Auth, rate-limit, and WAF decisions happen once, centrally.
- Every handler shares the same send queue → message ordering is deterministic per connection.
- Common diagnostics (bytes in/out, last-seen) live in one counter table.

## What the endpoints do

| Path                         | Purpose                                                                |
| ---------------------------- | ---------------------------------------------------------------------- |
| `/ws/chat/{room_id}`         | Room message stream (in + out, receipts, presence, typing).            |
| `/ws/signal/{room_id}`       | E2E key-rotation signals (room-key offers, device-added events).       |
| `/ws/stream/{room_id}`       | Live-stream control channel (hand-raise, reactions, donations).         |
| `/ws/voice-signal/{room_id}` | Voice-channel signalling (join/leave, mute state, stage mode).          |
| `/ws/sfu/{call_id}`          | SFU signalling proxy (the node just forwards to the SFU admin channel).|
| `/ws/notifications`          | Per-user cross-room notification stream (reactions, mentions, DMs).     |

## Not here

- Feature-specific handlers (the actual business logic of each WS path) live in `../chats/messages/ws_signal.py`, `../chats/stream.py`, `../chats/voice.py`, `../media/sfu_bridge.py`, etc. This folder only wires them up.

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
