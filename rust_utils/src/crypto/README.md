# `rust_utils/src/crypto/` — High-level Crypto Combos

Combinations of primitives that are useful beyond what `crypto.rs` exposes at the top level. Each helper here composes two or more primitives into a single operation with a single nonce/tag check.

## Helpers

- `seal_and_sign(msg, sym_key, sign_priv) -> (ct, sig)` — AES-GCM encrypt + Ed25519 sign the ciphertext.
- `verify_and_open(ct, sig, sym_key, sign_pub) -> msg` — reverse.
- `ecies_encrypt(msg, recipient_x25519_pub) -> (eph_pub, ct)` — ECIES with X25519 + HKDF + AES-GCM.
- `ecies_decrypt(eph_pub, ct, x25519_priv) -> msg`.
- `hkdf_expand_multiple(salt, ikm, labels[]) -> [keys]` — derive N keys in one call.
- `constant_time_equal(a, b) -> bool`.

## Why a sub-module

`crypto.rs` at the src root handles simple one-primitive operations. This folder is for everything that would otherwise live there but has enough code to warrant a `mod.rs` + helpers file.

## Tests

See `../../tests/messages_tests.rs` and the inline `#[cfg(test)]` blocks.

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
