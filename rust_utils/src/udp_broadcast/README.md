# `rust_utils/src/udp_broadcast/` — LAN Broadcast Extensions

Advanced discovery modes on top of `udp_broadcast.rs` (flat file at `../`). The flat file handles the basic "I am a Vortex node" broadcast on UDP/4200 — this folder adds multicast, multi-subnet, and replay protection.

## What's here

- **Multicast** variant for networks where broadcast is filtered but multicast (e.g. `239.x.y.z`) is allowed.
- **Multi-subnet** fan-out — send the same announce on every locally-connected interface, not just the default.
- **Replay protection** — each announce carries a monotonic counter + short-lived signature; receivers reject duplicates or future-dated announces.
- **Compact payload** — packs pubkey + endpoint + version flags into a single UDP datagram that fits within the default MTU.

## Why not in `udp_broadcast.rs`?

The single-file version is <200 lines and covers 80% of setups. Anything beyond that (multicast config, multi-NIC policy, signed replay window) adds enough state to deserve its own `mod.rs` + helpers.

## Tests

End-to-end tests spin up a mock "network" via `tokio::net::UdpSocket` loopback and exercise announce + receive across both transports.

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
