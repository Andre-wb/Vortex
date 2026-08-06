# `app/media/` — SFU Bridge

Selective Forwarding Unit (SFU) integration for group voice / video / streaming. A one-module package that only wraps the external SFU — the SFU itself lives out-of-process (it can be `mediasoup`, `Janus`, `livekit`, or any server that speaks a compatible signalling protocol).

## Files

| File            | Role                                                                          |
| --------------- | ----------------------------------------------------------------------------- |
| `sfu_bridge.py` | Creates short-lived scoped JWTs for clients, proxies signalling messages, tears down stale sessions. Enforces room membership before issuing a token. |

## Why an SFU

- **1-to-1 calls** go fully peer-to-peer over WebRTC. No SFU needed.
- **Small groups** (≤4) can still mesh P2P.
- **5+ participants** or broadcast streams route media through the SFU — fan-out is O(n) bandwidth per uplink instead of O(n²).

## Flow

```
client                    node                         SFU (external)
  │ POST /api/voice/join   │                              │
  │  { room_id }           │                              │
  │                        │ verify membership + perms    │
  │                        │ POST /admin/room (new)       │──▶
  │                        │ POST /admin/token (per user) │──▶
  │ ◀─────── { sfu_url, token, ice } ─────────────────────│
  │                                                       │
  │ wss://sfu/signal ──────────────────────────────────▶ │
  │ (WebRTC negotiation + media)                         │
```

The Vortex node **never proxies media bytes** — it only hands out scoped tokens and cleans up rooms when the last member leaves.

## Configuration

| Env var                  | Purpose                                           |
| ------------------------ | ------------------------------------------------- |
| `SFU_URL`                | Admin endpoint of the SFU (e.g. `http://sfu:7880`). |
| `SFU_API_KEY`, `SFU_API_SECRET` | Shared HMAC secret for minting tokens.     |
| `SFU_JWT_TTL_SECONDS`    | Token validity window (default 300).              |
| `SFU_RECORDINGS_DIR`     | Where the SFU stores recordings (if enabled).     |

## Related

- `app/chats/sfu.py` — thin router that exposes the bridge to clients.
- `app/chats/voice.py`, `app/chats/group_calls.py`, `app/chats/stream.py` — feature code that actually calls the bridge.
- `deploy/k8s/vortex.yaml` — includes an optional SFU sidecar/deployment example.

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
