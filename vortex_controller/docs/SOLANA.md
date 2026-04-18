# Vortex Registry on Solana (Phase 5)

The `solana_program/` directory contains an [Anchor](https://www.anchor-lang.com/)
program that stores Vortex peers as on-chain PDAs. Clients read the program
state directly, removing the HTTP controller as a trust root.

Who needs this
--------------

- Operators who want **fully trustless** peer discovery (no controller to
  compromise).
- Communities that want to **fork** the network: deploy a new program ID,
  nothing else changes.
- Auditors who want an **immutable log** of every node that ever existed.

The HTTP controller from Phase 1 still works. Phase 5 is **additive** — nodes
can register in both systems, and clients merge the lists.

---

## Prerequisites

```bash
# Rust toolchain (if missing)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

# Anchor
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install latest && avm use latest

# Node (for TS tests)
# Any recent Node.js 18+ works; nvm install --lts
```

Generate a Solana keypair and fund it on devnet:

```bash
solana-keygen new --outfile ~/.config/solana/id.json
solana config set --url devnet
solana airdrop 5
```

---

## 1. Build the program

```bash
cd solana_program
npm install   # pulls @coral-xyz/anchor for tests
anchor build
```

Anchor generates a fresh program ID during build. Update it in two places:

```bash
# Copy the new ID:
solana address -k target/deploy/vortex_registry-keypair.json

# Replace the declare_id! macro:
#   programs/vortex_registry/src/lib.rs  (declare_id!("..."))
#   Anchor.toml                          (programs.localnet / programs.devnet)

anchor build        # rebuild with the new id
```

---

## 2. Run the tests

```bash
anchor test        # spins up a local validator, deploys, runs ts-mocha
```

You should see four passing tests covering register / heartbeat / reject-empty
/ reject-wrong-owner / close.

---

## 3. Deploy

### Devnet (free, ephemeral)

```bash
anchor deploy --provider.cluster devnet
```

Write down the printed program ID. That's your `SOLANA_PROGRAM_ID`.

### Mainnet (real SOL required)

```bash
anchor deploy --provider.cluster mainnet
# ~2 SOL for deploy + rent on a ~200 KB program
```

Upgradeable by default. If you want **immutable** (fork-proof) deploy, add
`--final`:

```bash
anchor deploy --provider.cluster mainnet --final
```

---

## 4. Register your node

You can register from any wallet — the Anchor program accepts any Solana
keypair as the owner of a peer account.

### From TypeScript

```ts
import * as anchor from "@coral-xyz/anchor";
import { VortexRegistry } from "./target/types/vortex_registry";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);
const program = anchor.workspace.VortexRegistry as anchor.Program<VortexRegistry>;

const nodePubkey = /* 32-byte ed25519 pubkey of your Vortex node */;
const [pda] = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from("peer"), nodePubkey],
  program.programId,
);

await program.methods
  .register(
    Array.from(nodePubkey),
    ["wss://my.node.example:9000"],
    JSON.stringify({ name: "node-A", version: "1.0", region: "eu" }),
  )
  .accounts({
    peer: pda,
    owner: provider.wallet.publicKey,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .rpc();
```

### Heartbeat loop

Run every 5–10 min so clients consider you online:

```ts
await program.methods.heartbeat()
  .accounts({ peer: pda, owner: provider.wallet.publicKey })
  .rpc();
```

Rent is paid once at registration (~0.002 SOL for typical data); heartbeats
cost only the transaction fee (a few thousand lamports).

---

## 5. Point your Vortex nodes at the on-chain registry

Add to each node's `.env`:

```bash
SOLANA_RPC_URL=https://api.devnet.solana.com   # or a private RPC
SOLANA_PROGRAM_ID=<your deployed program id>
```

Now the node's `GET /api/session/migration-hint` returns peers from **both**
the HTTP controller (if configured) and the Solana registry. The merger
prefers on-chain entries — they're authoritative.

The Python client reads via plain `getProgramAccounts` RPC; there's no
dependency on `solana-py`. See `app/peer/solana_registry.py`.

---

## 6. Client discovery flow

With Phase 5, a client's bootstrap can be entirely on-chain:

```
1. Resolve vortexx.sol via SNS → get program_id + rpc_url from TXT record
2. RPC: getProgramAccounts(program_id) → list of peer PDAs
3. Filter by last_heartbeat within 10 minutes → live peers
4. Connect to any; use handoff (Phase 3) to migrate when needed
```

No HTTP controller, no DNS, no website — just a Solana RPC and a program ID.
If the controller is also running, clients can cross-verify.

---

## 7. Security notes

- **PDA seed uses the Vortex Ed25519 pubkey**, not the Solana owner key. So
  the same node can be reached by the same seed regardless of which Solana
  wallet paid the rent.
- **Owner-only writes**: only the Solana wallet that created the account can
  update / heartbeat / close. If you lose the wallet, the record will expire
  once clients stop considering it "online" (heartbeat gap > 10 min by default).
- **No on-chain Ed25519 verification**: the program does not check that you
  actually control the `node_pubkey`. An attacker could publish a bogus PDA
  claiming to be someone else's node — but they can't match the signed
  `/v1/nodes/random` envelope from the real node's HTTP controller, and the
  migration-hint merger dedupes by pubkey (Solana wins on conflict with the
  controller). For stronger identity, use the HTTP controller alongside.
- **Upgrade authority**: when you `anchor deploy`, your wallet becomes the
  upgrade authority. For a community network, transfer authority to a
  multisig or set `--final` to freeze the program.

---

## 8. Costs (as of 2026)

| Action | SOL | USD (SOL=$150) |
|--------|-----|----------------|
| Program deploy (first time) | ~2 | $300 |
| Peer registration (rent) | ~0.002 | $0.30 |
| Heartbeat (tx fee only) | ~0.000005 | $0.00075 |
| One year of heartbeats (every 10 min) | ~0.03 | $4.50 |

Nodes in countries with sanctions against Solana RPC access should run
their own RPC endpoint or rely on the HTTP controller / Phase 2 multihop.
