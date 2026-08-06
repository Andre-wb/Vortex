# `rust_utils/src/` — Rust Crate Source

Source of the `rust_utils` Rust crate. Every file is either a `pub mod` or a module directory with its own `mod.rs`. The public API is defined in `lib.rs` — everything else is internal.

See the crate-level [`../README.md`](../README.md) for build instructions and Python-side usage.

## Modules

### Top-level files

| File                    | Role                                                                 |
| ----------------------- | -------------------------------------------------------------------- |
| `lib.rs`                | Crate root. `#[pymodule]` entry point — registers every helper as a Python-visible function. |
| `auth.rs`               | Signed-challenge helpers (Ed25519 proof-of-possession).              |
| `batch_verify.rs`       | Batch Ed25519 verification — 10× throughput vs. per-signature loop. |
| `canonical_json.rs`     | RFC 8785-compatible JSON canonicalisation for stable signing.        |
| `chunk_hash.rs`         | Rolling BLAKE3 over upload chunks.                                   |
| `crypto.rs`             | One-shot crypto helpers — seal-and-sign, nonce+MAC envelope, etc.    |
| `integrity_walk.rs`     | Recursive BLAKE3 over a file tree (used by integrity manifests).     |
| `messages.rs`           | Wire-envelope pack/unpack (CBOR).                                    |
| `metadata_padding.rs`   | Constant-length padding buckets for message envelopes.               |
| `ratchet_kdf.rs`        | Double Ratchet KDF chain (MK + CK derivation).                       |
| `sealed_sender.rs`      | Signal-style sealed-sender envelope.                                 |
| `steganography.rs`      | LSB stego embedder for cover images.                                 |
| `udp_broadcast.rs`      | LAN peer-discovery broadcast protocol.                               |

### Sub-modules (directories with `mod.rs`)

| Dir               | Extends                                                                |
| ----------------- | ---------------------------------------------------------------------- |
| `auth/`           | Larger auth helpers that don't fit in the flat file.                   |
| `bmp/`            | BMP mailbox-ID derivation + cover-traffic mixing.                      |
| `crypto/`         | Higher-level crypto combos (e.g. seal+sign+authenticate).              |
| `messages/`       | Message-specific sub-helpers (attachments, fragmentation).             |
| `udp_broadcast/`  | Advanced discovery modes (multicast, multi-subnet).                    |

## Conventions

- **Stateless functions.** Callers own all state; this crate is a collection of pure operations.
- **Bytes in, bytes out.** Inputs are `&[u8]`, outputs are owned `Vec<u8>` or typed tuples. No `serde_json::Value`; canonicalisation happens inside dedicated helpers.
- **Errors** are `anyhow::Error` on the Rust side, converted to Python `ValueError` / `RuntimeError` at the FFI boundary.
- **No global mutable state.** Any cached thing lives in a `OnceLock` / `Lazy` with a clear warm-up cost.

## Testing

```bash
cargo test                     # unit + integration tests under tests/
cargo bench                    # criterion benches (if the `bench` feature is enabled)
```

Integration tests live at `../tests/messages_tests.rs`.

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
