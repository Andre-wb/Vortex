# `solana_program/programs/vortex_registry/` — Anchor Program Source

The Vortex peer registry Anchor program. 1,317 lines of Rust in `src/lib.rs`.

## Files

| File              | Role                                                              |
| ----------------- | ----------------------------------------------------------------- |
| `Cargo.toml`      | Crate manifest — Anchor version, program-id target, no-entrypoint flag. |
| `Xargo.toml`      | BPF-target linker hints (Anchor convention).                      |
| `src/lib.rs`      | The whole program — module declaration, `declare_id!`, constants, instructions, accounts, events, errors. |

## Phases

1. **Phase 5 — basic registry**: `initialize_config`, `register`, `update`, `deregister`.
2. **Phase 7 — code-integrity pinning**: `seal()` (one-way), `checkin(code_hash)` + events when the reported hash changes.
3. **Phase C — staking**: `stake`, `unstake` (cool-down gated), min + max bounds.
4. **Phase D — subscriptions + rewards**: `subscribe(tier)`, `claim_rewards`, `admin_update_config`.

See [`../../README.md`](../../README.md) for the constants table, PDA seeds, and deploy flow.

## Building

```bash
cd solana_program
anchor build                                  # produces the BPF binary
anchor keys list                              # pubkey of the built binary
# Replace declare_id!("...") in src/lib.rs with the output, then:
anchor build                                  # rebuild so declared id matches
```

## Program ID

The checked-in `declare_id!("8iNKGfNtAwZY8VLnoxardTstm5FFSePR5mN7LUyH4TRR")` is a valid-looking placeholder so the crate compiles before deployment. **Always** replace it with your actual build key (from `anchor keys list`) before deploying.

## Testing

Integration tests live at `../../tests/vortex_registry.ts`. Run via `anchor test` from the `solana_program/` root — it spins up a local validator and exercises every instruction.

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
