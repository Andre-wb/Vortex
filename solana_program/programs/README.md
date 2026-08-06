# `solana_program/programs/` — Anchor Program Workspace

Parent folder for every Anchor program shipped by Vortex. Currently just one — `vortex_registry`. Additional programs (if any are added later — tipping, staking rewards, treasury vault) would live as sibling folders here.

## `vortex_registry/`

The canonical on-chain peer registry for Vortex. Holds:

- Per-node PDA (endpoints, metadata, code_hash, heartbeat).
- Global config (register fee, tier prices, treasury pubkey, admin).
- Per-user subscription PDA (tier, paid-through timestamp).
- Per-node stake PDA + global rewards vault.
- Per-node accrued reward PDA.

See [`../README.md`](../README.md) for the full program overview, constants, PDAs, phases, and deploy flow. The source is in `vortex_registry/src/lib.rs` — **1,317 lines** of Anchor / Rust.

## Adding a new program

```bash
cd solana_program
anchor new <program_name>
```

Update `Cargo.toml` workspace members and `Anchor.toml` program keys. Follow the same convention: one `src/lib.rs` with the whole program; instructions as `pub fn`; account structs with `#[derive(Accounts)]`; errors via `#[error_code]`.

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
