# `rust_utils/` — Rust Crypto & Transport Helpers

Rust crate that exposes performance-critical helpers to Python via PyO3. Builds the `vortex_chat` extension module and covers crypto primitives plus the non-primitive helpers — BMP, canonical JSON, UDP broadcast, ratchet KDF, sealed sender, steganography, metadata padding.

Member of the root Cargo workspace together with `vortex_waf/`; the authoritative list of exported functions is the `#[pymodule]` block in `src/lib.rs`.

Everything here is deliberately **stateless**. State (keys, ratchets, counters) lives in Python; Rust just gets called with raw bytes in, raw bytes out.

## Layout

```
rust_utils/
├── Cargo.toml              ← crate config + PyO3 bindings
├── src/
│   ├── lib.rs              ← #[pymodule] — publishes every helper to Python
│   ├── auth.rs             ← auth-related helpers (challenge signing, HMAC)
│   ├── auth/               ← sub-module for larger auth helpers
│   ├── batch_verify.rs     ← batch Ed25519 signature verification
│   ├── bmp/                ← Blind Mailbox Protocol — mailbox id derivation, cover-traffic mixing
│   ├── canonical_json.rs   ← RFC 8785-compatible JSON canonicalisation for signing
│   ├── chunk_hash.rs       ← rolling BLAKE3 over upload chunks
│   ├── crypto.rs           ← one-shot crypto helpers (layered on vortex_chat)
│   ├── crypto/             ← sub-module for higher-level combos (seal + sign, etc.)
│   ├── integrity_walk.rs   ← recursive file-tree BLAKE3 for INTEGRITY manifests
│   ├── messages.rs         ← wire envelope pack/unpack (CBOR)
│   ├── messages/           ← message-specific sub-helpers
│   ├── metadata_padding.rs ← constant-length padding for message envelopes
│   ├── ratchet_kdf.rs      ← Double Ratchet KDF chain + MK/CK derivation
│   ├── sealed_sender.rs    ← Signal-style sealed-sender envelope
│   ├── steganography.rs    ← bit-level LSB embedder for cover images
│   ├── udp_broadcast.rs    ← LAN broadcast protocol for peer discovery
│   └── udp_broadcast/      ← sub-module for advanced discovery modes
└── tests/
    └── messages_tests.rs   ← Rust-side unit tests for the wire format
```

## Building

Built via maturin so Python can `import vortex_chat`:

```bash
make rust-build                                        # both extensions into the active venv
maturin develop --release -m rust_utils/Cargo.toml     # this crate only
maturin build   --release -m rust_utils/Cargo.toml     # standalone wheel
```

Workspace-wide checks run from the repository root:

```bash
make rust-check      # cargo test --workspace + clippy -D warnings + fmt --check
```

The `extension-module` feature is **not** on by default — without it `cargo test` cannot link. Maturin turns it on via `features = ["extension-module"]` in `pyproject.toml`.

During the PyInstaller wizard build, the compiled extension is picked up automatically via `collect_all("vortex_chat")` in `vortex-wizard.spec`.

## Python surface (selected)

```python
import vortex_chat

# BMP
mailbox_id  = vortex_chat.bmp_compute_mailbox_id(secret_hex, timestamp)
mailbox_ids = vortex_chat.bmp_compute_mailbox_ids(secret_hex, timestamp)

# Canonical JSON (for signing)
canon = vortex_chat.canonical_json(obj)               # bytes, stable ordering
sig   = vortex_chat.sign_canonical(priv_raw, obj)     # hex ed25519 signature

# Ratchet
new_ck, mk = vortex_chat.ratchet_kdf_ck(ck)
root, chain = vortex_chat.ratchet_kdf_rk(rk, dh_out)

# Integrity
manifest = vortex_chat.sha256_manifest_walk(path)     # parallel SHA-256

# Sealed sender
pseudo = vortex_chat.compute_sender_pseudo(secret, room_id, sender_id)
```

Cross-language parity with the Python fallbacks is pinned by `app/tests/test_rust_parity.py` against the frozen vectors in `app/tests/vectors/rust_parity.json`.

## Test

```bash
cargo test                     # Rust-side tests (fast, no Python)
pytest app/tests/test_crypto_core.py -k rust_utils  # Python-side integration
```

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
