# `solana_program/` — On-chain Peer Registry (Anchor)

The Solana program that holds the permissionless truth about the Vortex network: who's a node, what build they're running, who's paid for premium, and how rewards are distributed.

See the program source under `programs/vortex_registry/` — **1,317 lines** of Anchor / Rust covering Phases 5 (basic registry), 7 (code-integrity pinning), C (staking), and D (subscriptions + rewards).

## Layout

| Path                       | Role                                                                 |
| -------------------------- | -------------------------------------------------------------------- |
| `Anchor.toml`              | Cluster + wallet config for `anchor build` / `anchor deploy`.         |
| `Cargo.toml`               | Workspace file — references `programs/vortex_registry/`.              |
| `package.json`             | TypeScript tooling for tests and ops scripts.                         |
| `tsconfig.json`            | TS compile settings for `scripts/` and `tests/`.                      |
| `deploy.sh`                | Opinionated build + deploy pipeline — see "Deploy" below.             |
| `programs/vortex_registry/` | The Anchor program itself. `src/lib.rs` has PDAs, instructions, and events. |
| `scripts/`                 | Operator scripts (see below).                                         |
| `tests/vortex_registry.ts` | Full integration test suite — spins up a local validator, exercises every instruction. |

### `programs/vortex_registry/src/lib.rs` — key constants

| Constant                              | Value          | Purpose                                                     |
| ------------------------------------- | -------------- | ----------------------------------------------------------- |
| `DEFAULT_REGISTER_FEE_LAMPORTS`       | 1 SOL          | Initial register fee (admin can tune).                      |
| `MAX_REGISTER_FEE_LAMPORTS`           | 10 SOL         | Hard upper bound so a compromised admin key can't weaponise the fee. |
| `PLAN_DURATIONS_MONTHS`               | [1, 3, 6, 12]  | Supported subscription plans.                               |
| `DEFAULT_TIER_PRICES_LAMPORTS`        | ~$5/$12/$20/$38 | Defaults at ~$150/SOL. Monotone: yearly is strictly cheaper per-month than two 6-month. |
| `MAX_TIER_PRICE_LAMPORTS`             | 6 SOL          | Cap per plan (~$900 max even if SOL moons).                 |
| `SECONDS_PER_MONTH`                   | 30 × 86_400    | Fixed-length month for deterministic accounting.            |
| `MIN_STAKE_LAMPORTS`                  | 0.1 SOL        | Minimum stake per node (dust protection).                   |

### PDAs (seed prefixes)

| Seed              | PDA purpose                                               |
| ----------------- | --------------------------------------------------------- |
| `peer`            | Per-node registration (endpoints, metadata, code_hash).    |
| `config`          | Global registry config (fee, tier prices, treasury).      |
| `subscription`    | Per-user premium subscription state.                      |
| `stake`           | Per-node stake account.                                   |
| `rewards_vault`   | Treasury rewards pool.                                    |
| `reward`          | Per-node accrued reward account.                          |

## `scripts/`

| Script                | What it does                                                         |
| --------------------- | -------------------------------------------------------------------- |
| `init_mainnet.ts`     | One-shot initialisation on mainnet — calls `initialize_config` with real values, creates the treasury rewards vault. |
| `buy_premium.ts`      | Reference client flow — derive subscription PDA, pay, read back end timestamp. Used by integrators who need an end-to-end check. |

Run with:

```bash
cd solana_program
npm install
anchor build
ts-node scripts/init_mainnet.ts            # once, on deploy
ts-node scripts/buy_premium.ts --months 1  # sanity check
```

## Deploy

```bash
cd solana_program
anchor build                                # builds the BPF binary
anchor keys list                            # print the program pubkey from the built binary
# Replace declare_id!("...") in programs/vortex_registry/src/lib.rs with the output
anchor build                                # rebuild so pubkey matches
anchor deploy --provider.cluster mainnet    # or devnet / localnet
```

The `deploy.sh` script wraps this with guard-rails: it refuses to deploy if `declare_id!` still carries the placeholder, and refuses to deploy mainnet unless the local wallet's balance is above a configured threshold.

## Testing

```bash
# spin up a local validator with the program pre-loaded
anchor test                                 # runs tests/vortex_registry.ts end-to-end
```

The test suite exercises: `initialize_config`, `register` (with and without stake), `update`, `checkin` (same and changed code_hash), `seal` (and rejection of re-seal with different hash), `subscribe` (every tier), `deregister`, rewards accrual + claim, admin fee update (happy path + hard-cap rejection).

## Integration with the rest of Vortex

- **Controller (`vortex_controller/`)** reads live peer state from this program and cross-checks it against its own heartbeat table.
- **Node (`app/peer/solana_registry.py`)** resolves peer records on-demand via Solana RPC; trust weight decays with `last_checkin` age.
- **Premium module** on iOS / Android / web reads subscription PDAs directly when the node can't be reached (censorship fallback).
- **Treasury wallet** is the SNS owner of `vortexx.sol` by default (`5ABkkipTZZEEPNR3cP4MCzftpAhqv6jvM4UTSLPGt5Qq`). Override via `TREASURY_PUBKEY` for forks/testnets.

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
