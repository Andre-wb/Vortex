# `solana_program/scripts/` — Operator Scripts

TypeScript scripts for one-off operator actions against the deployed `vortex_registry` program. Meant to be run via `ts-node` after `npm install` and `anchor build`.

## Files

| Script             | What it does                                                                       |
| ------------------ | ---------------------------------------------------------------------------------- |
| `init_mainnet.ts`  | One-shot initialisation on mainnet. Calls `initialize_config` with production values: treasury pubkey (`vortexx.sol` owner by default), initial fee (1 SOL), default tier prices. Creates the global rewards vault PDA. **Run once per deployment.** |
| `buy_premium.ts`   | Reference client flow for the premium subscription. Derives the subscription PDA, pays the tier amount, reads back the `paid_through_ts` so integrators can mirror the flow in their own clients. Accepts `--months 1|3|6|12`. |

## Running

```bash
cd solana_program
npm install
anchor build                             # produces target/idl/vortex_registry.json

# Point Anchor at the network you want (mainnet | devnet | localnet)
export ANCHOR_PROVIDER_URL=https://api.mainnet-beta.solana.com
export ANCHOR_WALLET=~/.config/solana/id.json

ts-node scripts/init_mainnet.ts          # dangerous — only once per deployment
ts-node scripts/buy_premium.ts --months 1
```

## Guard-rails

- `init_mainnet.ts` refuses to run if:
  - `config` PDA already exists (already initialized), or
  - the connected wallet's balance is below a configured threshold.
- `buy_premium.ts` prints the computed PDA + expected lamport cost before submitting; the user must confirm.

## Conventions

- Each script is standalone — no shared helper file, so you can copy one into another project without dragging dependencies.
- `Anchor.toml`'s `[programs]` block supplies the program id; scripts read it via `anchor.workspace.<Program>`.

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
