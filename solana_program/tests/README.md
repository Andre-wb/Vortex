# `solana_program/tests/` — Anchor Integration Tests

Integration tests for the `vortex_registry` program. `anchor test` spins up a local validator with the program pre-loaded and runs these TypeScript tests against it.

## Files

| File                   | Covers                                                                            |
| ---------------------- | --------------------------------------------------------------------------------- |
| `vortex_registry.ts`   | End-to-end suite for every instruction.                                           |

## Covered flows

- **Config init**: happy path, rejects re-initialisation, fee cap enforced.
- **Register**: without stake, with stake (≥ `MIN_STAKE_LAMPORTS`), rejects under minimum, rejects overflow near `MAX_STAKE_LAMPORTS`.
- **Update**: only owner; rejects if `is_sealed=true` and code_hash would change.
- **Checkin**: same hash (no-op event), changed hash (event + stored), past-deadline rejection.
- **Seal**: one-way; rejects re-seal with different hash; no-op re-seal with same hash.
- **Subscribe**: every tier (1/3/6/12 months); computes correct `paid_through_ts`; enforces current tier price; rejects downgrade during active period (unless admin policy allows).
- **Stake / unstake**: deposit, withdraw with cool-down, dust-attack rejection.
- **Rewards**: accrual math over several `checkin` cycles; claim with insufficient vault balance fails gracefully.
- **Deregister**: returns rent to owner; rejects if subscription active and admin policy forbids; cleans up related PDAs.
- **Admin fee update**: happy path; rejects above `MAX_REGISTER_FEE_LAMPORTS`; only admin key can call.

## Running

```bash
cd solana_program
npm install
anchor test                   # brings up a local validator, loads the program, runs tests
```

Takes ~30–60s on a modern laptop.

## Conventions

- Use `anchor.workspace.VortexRegistry` — do not hard-code the program id.
- Each test derives its own PDAs from `anchor.utils.publicKey.findProgramAddressSync`.
- Clean-up: tests intentionally do NOT call `deregister` at the end — Anchor wipes the validator between runs, so cleanup is unnecessary and makes tests faster.
- Assertions via `chai`.

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
