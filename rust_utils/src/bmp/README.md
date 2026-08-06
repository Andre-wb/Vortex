# `rust_utils/src/bmp/` — BMP (Blind Mailbox Protocol)

Rust implementation of Vortex's metadata-obfuscation layer. See `RESEARCH-BMP.md` at the repo root for the design document.

## What's here

- `mailbox_id(shared_secret, epoch_seconds, period)` — derives the current mailbox ID:
  ```
  mailbox_id(t) = HMAC-SHA256(S_AB, floor(t / T))[0:16]
  ```
- `generate_covers(real_ids, count)` — wraps real mailbox IDs with `count` cryptographically random decoys and shuffles the result.
- Helpers for epoch math and envelope packing.

## Exposed to Python

```python
import rust_utils

mid    = rust_utils.bmp_mailbox_id(shared_secret, time.time(), period=3600)
poll   = rust_utils.bmp_generate_covers(real_ids=[mid], count=50)
```

## Performance

- Mailbox derivation: ~0.5µs per call (HMAC-SHA256 throughput dominated).
- Cover generation: O(n) in decoy count; single BLAKE3 + Fisher–Yates shuffle.

## Tests

Round-trip test: two parties derive the same mailbox ID from their own private key + the other's public key. Also verifies epoch rollover (one party querying at `t - 1s`, the other at `t + 1s`, both still agreeing within the same epoch).

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
