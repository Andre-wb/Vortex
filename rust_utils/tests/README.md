# `rust_utils/tests/` — Integration Tests

Rust-side integration tests for the `rust_utils` crate. Compiled as separate binaries that link against the crate as an external dependency — so they exercise only the public API, not module-internal helpers.

## Files

| File                  | Covers                                                                 |
| --------------------- | ---------------------------------------------------------------------- |
| `messages_tests.rs`   | Wire-envelope pack/unpack round-trip, CBOR stability, version bumps, corrupt-input refusal. |

(Unit tests for individual modules live inline with the source in `../src/<file>.rs` under `#[cfg(test)] mod tests`.)

## Running

```bash
cd rust_utils
cargo test                   # runs both unit tests and integration tests
cargo test --test messages_tests -- --nocapture   # just the integration tests, with println! output
```

## Adding a test

1. Add a file here named `<topic>_tests.rs`.
2. Use `use rust_utils::…;` — only public items are reachable.
3. Each test is `#[test] fn test_<name>()`.
4. Keep each test self-contained — no `setup.rs` helper file across tests.

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
