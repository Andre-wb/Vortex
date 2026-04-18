/**
 * Integration tests for the Vortex on-chain peer registry.
 *
 * Run with:
 *   anchor test
 *
 * The tests spin up a local validator via anchor, deploy the program, and
 * exercise every instruction. A new Keypair stands in for each node's
 * Ed25519 identity.
 */
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { VortexRegistry } from "../target/types/vortex_registry";
import { assert } from "chai";

describe("vortex_registry", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.VortexRegistry as Program<VortexRegistry>;

  const nodePubkey = Buffer.alloc(32);
  nodePubkey.write("vortex-test-node-0123456789abcdef", "utf8");

  function peerPda(nodeKey: Buffer): anchor.web3.PublicKey {
    const [pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("peer"), nodeKey],
      program.programId,
    );
    return pda;
  }

  it("registers a new peer", async () => {
    const pda = peerPda(nodePubkey);
    await program.methods
      .register(
        Array.from(nodePubkey) as any,
        ["wss://node-a.example:9000"],
        '{"name":"node-A","region":"eu"}',
      )
      .accounts({
        peer: pda,
        owner: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const acc = await program.account.peer.fetch(pda);
    assert.deepEqual(Array.from(acc.nodePubkey), Array.from(nodePubkey));
    assert.equal(acc.endpoints.length, 1);
    assert.equal(acc.endpoints[0], "wss://node-a.example:9000");
    assert.equal(acc.metadata, '{"name":"node-A","region":"eu"}');
    assert.isTrue(acc.owner.equals(provider.wallet.publicKey));
    assert.isTrue(acc.registeredAt.toNumber() > 0);
    assert.equal(acc.registeredAt.toNumber(), acc.lastHeartbeat.toNumber());
  });

  it("updates last_heartbeat on heartbeat()", async () => {
    const pda = peerPda(nodePubkey);
    const before = await program.account.peer.fetch(pda);
    await new Promise((r) => setTimeout(r, 1100));
    await program.methods
      .heartbeat()
      .accounts({ peer: pda, owner: provider.wallet.publicKey })
      .rpc();
    const after = await program.account.peer.fetch(pda);
    assert.isAtLeast(after.lastHeartbeat.toNumber(), before.lastHeartbeat.toNumber() + 1);
    assert.equal(after.registeredAt.toNumber(), before.registeredAt.toNumber());
  });

  it("rejects empty endpoints", async () => {
    const fresh = Buffer.alloc(32);
    fresh.write("empty-endpoints-test-node", "utf8");
    const pda = peerPda(fresh);
    try {
      await program.methods
        .register(Array.from(fresh) as any, [], "{}")
        .accounts({
          peer: pda,
          owner: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      assert.fail("should have rejected empty endpoints");
    } catch (e: any) {
      assert.include(String(e), "endpoints list must not be empty");
    }
  });

  it("rejects heartbeat from non-owner", async () => {
    const pda = peerPda(nodePubkey);
    const other = anchor.web3.Keypair.generate();
    try {
      await program.methods
        .heartbeat()
        .accounts({ peer: pda, owner: other.publicKey })
        .signers([other])
        .rpc();
      assert.fail("should have rejected wrong owner");
    } catch (e: any) {
      assert.include(String(e), "NotOwner");
    }
  });

  it("closes peer and refunds rent", async () => {
    const pda = peerPda(nodePubkey);
    await program.methods
      .closePeer()
      .accounts({ peer: pda, owner: provider.wallet.publicKey })
      .rpc();

    const gone = await provider.connection.getAccountInfo(pda);
    assert.isNull(gone, "peer account should be closed");
  });

  // ── Phase A: treasury + register-fee ─────────────────────────────────
  describe("phase A — register fee + config", () => {
    const [configPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      program.programId,
    );

    // Treasury is just a regular SystemProgram-owned keypair. Any account
    // that appears on the right side of a transfer works.
    const treasury = anchor.web3.Keypair.generate();

    it("initializes the config PDA", async () => {
      await program.methods
        .initializeConfig(treasury.publicKey)
        .accounts({
          config: configPda,
          admin: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();

      const cfg = await program.account.config.fetch(configPda);
      assert.isTrue(cfg.admin.equals(provider.wallet.publicKey));
      assert.isTrue(cfg.treasury.equals(treasury.publicKey));
      assert.equal(cfg.registerFeeLamports.toNumber(), 1_000_000_000);
      assert.equal(cfg.registrationsCount.toNumber(), 0);
      assert.equal(cfg.totalFeesCollected.toNumber(), 0);
    });

    it("register_with_fee transfers 1 SOL to the treasury and sets fee_paid", async () => {
      const node = Buffer.alloc(32);
      node.write("fee-paid-node-0001", "utf8");
      const pda = peerPda(node);

      const before = await provider.connection.getBalance(treasury.publicKey);

      await program.methods
        .registerWithFee(
          Array.from(node) as any,
          ["wss://paid-node.example:9000"],
          '{"name":"paid"}',
        )
        .accounts({
          config: configPda,
          peer: pda,
          owner: provider.wallet.publicKey,
          treasury: treasury.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();

      const after = await provider.connection.getBalance(treasury.publicKey);
      assert.equal(after - before, 1_000_000_000, "treasury must receive exactly 1 SOL");

      const peer = await program.account.peer.fetch(pda);
      assert.isTrue(peer.feePaid, "peer.feePaid must be true after register_with_fee");
      assert.isAtLeast(peer.feePaidAt.toNumber(), 1, "fee_paid_at must be set");

      const cfg = await program.account.config.fetch(configPda);
      assert.equal(cfg.registrationsCount.toNumber(), 1);
      assert.equal(cfg.totalFeesCollected.toNumber(), 1_000_000_000);
    });

    it("rejects register_with_fee when wrong treasury is passed", async () => {
      const node = Buffer.alloc(32);
      node.write("wrong-treasury-test", "utf8");
      const pda = peerPda(node);
      const fake = anchor.web3.Keypair.generate();

      try {
        await program.methods
          .registerWithFee(
            Array.from(node) as any,
            ["wss://x.example"],
            "{}",
          )
          .accounts({
            config: configPda,
            peer: pda,
            owner: provider.wallet.publicKey,
            treasury: fake.publicKey,
            systemProgram: anchor.web3.SystemProgram.programId,
          })
          .rpc();
        assert.fail("expected WrongTreasury error");
      } catch (e: any) {
        assert.include(String(e), "WrongTreasury");
      }
    });

    it("update_config lets admin change treasury + fee, rejects caps", async () => {
      const newTreasury = anchor.web3.Keypair.generate();
      await program.methods
        .updateConfig(newTreasury.publicKey, new anchor.BN(500_000_000))
        .accounts({ config: configPda, admin: provider.wallet.publicKey })
        .rpc();

      const cfg = await program.account.config.fetch(configPda);
      assert.isTrue(cfg.treasury.equals(newTreasury.publicKey));
      assert.equal(cfg.registerFeeLamports.toNumber(), 500_000_000);

      // Revert to original treasury for subsequent tests / idempotence.
      await program.methods
        .updateConfig(treasury.publicKey, new anchor.BN(1_000_000_000))
        .accounts({ config: configPda, admin: provider.wallet.publicKey })
        .rpc();

      // Above-cap fee must be rejected.
      try {
        await program.methods
          .updateConfig(null, new anchor.BN(100_000_000_000))
          .accounts({ config: configPda, admin: provider.wallet.publicKey })
          .rpc();
        assert.fail("expected FeeAboveCap error");
      } catch (e: any) {
        assert.include(String(e), "FeeAboveCap");
      }
    });

    it("update_config rejects non-admin signer", async () => {
      const other = anchor.web3.Keypair.generate();
      try {
        await program.methods
          .updateConfig(null, new anchor.BN(0))
          .accounts({ config: configPda, admin: other.publicKey })
          .signers([other])
          .rpc();
        assert.fail("expected NotOwner error");
      } catch (e: any) {
        assert.include(String(e), "NotOwner");
      }
    });
  });
});
