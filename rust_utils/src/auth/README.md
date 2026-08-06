# `rust_utils/src/auth/` — Signed Challenge Helpers

Ed25519 proof-of-possession helpers used by the node-side key-login + federation link flows. Complements `auth.rs` at the parent level — which holds the simple `sign_challenge(nonce) -> sig` / `verify_challenge(nonce, sig, pub) -> bool` primitives — with higher-level compositions.

## What's here

- **Challenge / response pairs** — `make_challenge()` produces a bound (nonce, issued_at, context_hash), `verify_response(challenge, sig, pub)` checks all three.
- **Batch verification** — when the caller has N signed challenges to verify (e.g. federation handshake + key publish), `batch_verify_context(responses)` verifies them in one go via `ed25519-dalek` batch path (~10× throughput vs. individual verify).
- **Issuance policy** — an opaque token that carries expiry, subject, and audience; signed by the controller or the node itself depending on the flow.

## Tests

Covered by `../../tests/messages_tests.rs` (section `auth_*`) and inline `#[cfg(test)]` mods.

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
