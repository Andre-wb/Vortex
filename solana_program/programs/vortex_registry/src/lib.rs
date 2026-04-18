//! Vortex on-chain peer registry (Phase 5 + 7).
//!
//! Phase 5 primitives:
//! - PDA at `["peer", node_pubkey]` stores endpoints + metadata + heartbeat.
//! - Anyone with SOL to cover rent can self-register a node.
//!
//! Phase 7 additions — permanent code-integrity pinning and trust decay:
//! - `code_hash` field locks the node to a specific build.
//! - `seal()` is a one-way instruction: once set, `is_sealed` flips forever.
//! - `checkin()` records that the node is still actively attesting to a
//!   specific `code_hash`; if the reported hash differs, we persist the new
//!   one but keep an on-chain audit trail via events.
//! - Off-chain consumers compute a `weight` based on `last_checkin` age so
//!   stale nodes stop receiving traffic.

use anchor_lang::prelude::*;
use anchor_lang::system_program;

// Placeholder program id — replace with `anchor keys list` output after
// `anchor build` so the deployed binary's pubkey matches. The existing
// value must still be a valid 32-byte base58 pubkey for the Rust crate
// to compile.
declare_id!("Vor1exReg1111111111111111111111111111111111");

pub const MAX_ENDPOINT_LEN: usize = 256;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_METADATA_LEN: usize = 512;
pub const NODE_PUBKEY_LEN: usize = 32;
pub const CODE_HASH_LEN: usize = 32;

pub const PEER_SEED:   &[u8] = b"peer";
pub const CONFIG_SEED: &[u8] = b"config";

/// Default register fee (1 SOL). Admin can change it at runtime via
/// ``update_config``; this constant is only the initial value.
pub const DEFAULT_REGISTER_FEE_LAMPORTS: u64 = 1_000_000_000;

/// Hard upper bound so a compromised admin key cannot weaponise the fee.
pub const MAX_REGISTER_FEE_LAMPORTS: u64 = 10_000_000_000; // 10 SOL

#[program]
pub mod vortex_registry {
    use super::*;

    /// Register (or refresh) a peer record. Does NOT seal.
    pub fn register(
        ctx: Context<Register>,
        node_pubkey: [u8; NODE_PUBKEY_LEN],
        endpoints: Vec<String>,
        metadata: String,
    ) -> Result<()> {
        validate_endpoints(&endpoints)?;
        require!(metadata.len() <= MAX_METADATA_LEN, VortexError::MetadataTooLong);

        let clock = Clock::get()?;
        let peer = &mut ctx.accounts.peer;
        peer.owner = ctx.accounts.owner.key();
        peer.node_pubkey = node_pubkey;
        peer.endpoints = endpoints;
        peer.metadata = metadata;
        peer.registered_at = clock.unix_timestamp;
        peer.last_heartbeat = clock.unix_timestamp;
        peer.last_checkin = clock.unix_timestamp;
        peer.bump = ctx.bumps.peer;
        // code_hash and is_sealed start zero until seal() is called
        Ok(())
    }

    /// Lightweight liveness ping — updates ``last_heartbeat`` only.
    pub fn heartbeat(ctx: Context<Heartbeat>) -> Result<()> {
        let peer = &mut ctx.accounts.peer;
        require!(peer.owner == ctx.accounts.owner.key(), VortexError::NotOwner);
        let clock = Clock::get()?;
        peer.last_heartbeat = clock.unix_timestamp;
        Ok(())
    }

    /// Replace endpoints/metadata. Owner-only.
    pub fn update(
        ctx: Context<Heartbeat>,
        endpoints: Vec<String>,
        metadata: String,
    ) -> Result<()> {
        validate_endpoints(&endpoints)?;
        require!(metadata.len() <= MAX_METADATA_LEN, VortexError::MetadataTooLong);

        let peer = &mut ctx.accounts.peer;
        require!(peer.owner == ctx.accounts.owner.key(), VortexError::NotOwner);
        let clock = Clock::get()?;
        peer.endpoints = endpoints;
        peer.metadata = metadata;
        peer.last_heartbeat = clock.unix_timestamp;
        Ok(())
    }

    /// **One-way** seal of the node's current code hash.
    ///
    /// After this runs, ``is_sealed`` is true forever. Clients treat any
    /// future divergence between the on-chain ``code_hash`` and what
    /// ``/v1/integrity`` reports as a tampered node.
    ///
    /// The owner can still update the hash via ``checkin()``, but every
    /// such change is emitted as an on-chain event so users see a full
    /// audit trail.
    pub fn seal(
        ctx: Context<Heartbeat>,
        code_hash: [u8; CODE_HASH_LEN],
    ) -> Result<()> {
        let peer = &mut ctx.accounts.peer;
        require!(peer.owner == ctx.accounts.owner.key(), VortexError::NotOwner);
        require!(!peer.is_sealed, VortexError::AlreadySealed);

        let clock = Clock::get()?;
        peer.code_hash = code_hash;
        peer.is_sealed = true;
        peer.first_sealed_at = clock.unix_timestamp;
        peer.last_checkin = clock.unix_timestamp;
        emit!(SealEvent {
            node_pubkey: peer.node_pubkey,
            code_hash,
            at: clock.unix_timestamp,
        });
        Ok(())
    }

    /// Periodic attestation that the node is still alive **and** still
    /// running the expected code. Operators call this every ~30 days.
    ///
    /// If the supplied ``code_hash`` differs from what's stored, we take
    /// the new value AND emit an ``UpdatedEvent`` — the full history of
    /// code changes stays visible on-chain.
    pub fn checkin(
        ctx: Context<Heartbeat>,
        code_hash: [u8; CODE_HASH_LEN],
    ) -> Result<()> {
        let peer = &mut ctx.accounts.peer;
        require!(peer.owner == ctx.accounts.owner.key(), VortexError::NotOwner);
        require!(peer.is_sealed, VortexError::NotSealed);

        let clock = Clock::get()?;
        if peer.code_hash != code_hash {
            emit!(UpdatedEvent {
                node_pubkey: peer.node_pubkey,
                old_hash: peer.code_hash,
                new_hash: code_hash,
                at: clock.unix_timestamp,
            });
            peer.code_hash = code_hash;
        }
        peer.last_checkin = clock.unix_timestamp;
        peer.last_heartbeat = clock.unix_timestamp;
        Ok(())
    }

    /// Close the peer account and return rent to the owner.
    pub fn close_peer(_ctx: Context<ClosePeer>) -> Result<()> {
        Ok(())
    }

    // ── Phase A: treasury + register-fee ───────────────────────────────

    /// Create the singleton program config.
    ///
    /// Called once by whoever sets up the program — typically the same
    /// key that owns the treasury. After this runs, ``register_with_fee``
    /// becomes usable. ``initialize_config`` cannot overwrite an existing
    /// config because the PDA init would fail.
    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        treasury: Pubkey,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.treasury = treasury;
        cfg.register_fee_lamports = DEFAULT_REGISTER_FEE_LAMPORTS;
        cfg.total_fees_collected = 0;
        cfg.registrations_count = 0;
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    /// Admin-only update of treasury destination and/or fee amount.
    ///
    /// ``new_treasury`` / ``new_fee_lamports`` are both optional — pass
    /// ``None`` to leave a field untouched. This is safer than a full
    /// overwrite because the caller cannot silently reset counters.
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        new_treasury: Option<Pubkey>,
        new_fee_lamports: Option<u64>,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(cfg.admin == ctx.accounts.admin.key(), VortexError::NotOwner);

        if let Some(t) = new_treasury {
            cfg.treasury = t;
        }
        if let Some(f) = new_fee_lamports {
            require!(f <= MAX_REGISTER_FEE_LAMPORTS, VortexError::FeeAboveCap);
            cfg.register_fee_lamports = f;
        }
        Ok(())
    }

    /// Register a peer AND pay the one-time on-chain register fee.
    ///
    /// Lamports are transferred from the owner to the treasury via the
    /// system program in the same transaction as the Peer PDA init, so
    /// either both succeed or both fail — a half-paid-but-registered
    /// state cannot exist on-chain.
    ///
    /// The Peer account is marked ``fee_paid = true`` so the controller
    /// and clients can tell at a glance whether a peer completed the
    /// anti-sybil step.
    pub fn register_with_fee(
        ctx: Context<RegisterWithFee>,
        node_pubkey: [u8; NODE_PUBKEY_LEN],
        endpoints: Vec<String>,
        metadata: String,
    ) -> Result<()> {
        validate_endpoints(&endpoints)?;
        require!(metadata.len() <= MAX_METADATA_LEN, VortexError::MetadataTooLong);

        let cfg = &ctx.accounts.config;
        require!(
            ctx.accounts.treasury.key() == cfg.treasury,
            VortexError::WrongTreasury,
        );

        // 1. Transfer the fee before writing any state, so a failed
        //    transfer aborts the whole instruction.
        let fee = cfg.register_fee_lamports;
        if fee > 0 {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.owner.to_account_info(),
                    to:   ctx.accounts.treasury.to_account_info(),
                },
            );
            system_program::transfer(cpi_ctx, fee)?;
        }

        // 2. Initialize / refresh the peer account.
        let clock = Clock::get()?;
        let peer = &mut ctx.accounts.peer;
        peer.owner = ctx.accounts.owner.key();
        peer.node_pubkey = node_pubkey;
        peer.endpoints = endpoints;
        peer.metadata = metadata;
        peer.registered_at = clock.unix_timestamp;
        peer.last_heartbeat = clock.unix_timestamp;
        peer.last_checkin = clock.unix_timestamp;
        peer.bump = ctx.bumps.peer;
        peer.fee_paid = true;
        peer.fee_paid_at = clock.unix_timestamp;

        // 3. Update counters on config (best-effort saturating math so a
        //    hypothetical overflow can never brick the program).
        let cfg_mut = &mut ctx.accounts.config;
        cfg_mut.total_fees_collected =
            cfg_mut.total_fees_collected.saturating_add(fee);
        cfg_mut.registrations_count =
            cfg_mut.registrations_count.saturating_add(1);

        emit!(RegisterFeePaid {
            node_pubkey,
            owner: ctx.accounts.owner.key(),
            treasury: ctx.accounts.treasury.key(),
            amount_lamports: fee,
            at: clock.unix_timestamp,
        });
        Ok(())
    }
}

fn validate_endpoints(endpoints: &Vec<String>) -> Result<()> {
    require!(!endpoints.is_empty(), VortexError::EmptyEndpoints);
    require!(endpoints.len() <= MAX_ENDPOINTS, VortexError::TooManyEndpoints);
    for e in endpoints.iter() {
        require!(!e.is_empty(), VortexError::EmptyEndpoint);
        require!(e.len() <= MAX_ENDPOINT_LEN, VortexError::EndpointTooLong);
    }
    Ok(())
}

#[derive(Accounts)]
#[instruction(node_pubkey: [u8; NODE_PUBKEY_LEN], endpoints: Vec<String>, metadata: String)]
pub struct Register<'info> {
    #[account(
        init_if_needed,
        payer = owner,
        space = Peer::space_for(&endpoints, &metadata),
        seeds = [PEER_SEED, node_pubkey.as_ref()],
        bump,
    )]
    pub peer: Account<'info, Peer>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Heartbeat<'info> {
    #[account(mut)]
    pub peer: Account<'info, Peer>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClosePeer<'info> {
    #[account(mut, close = owner, has_one = owner @ VortexError::NotOwner)]
    pub peer: Account<'info, Peer>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = Config::SIZE,
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(node_pubkey: [u8; NODE_PUBKEY_LEN], endpoints: Vec<String>, metadata: String)]
pub struct RegisterWithFee<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        init_if_needed,
        payer = owner,
        space = Peer::space_for(&endpoints, &metadata),
        seeds = [PEER_SEED, node_pubkey.as_ref()],
        bump,
    )]
    pub peer: Account<'info, Peer>,

    #[account(mut)]
    pub owner: Signer<'info>,

    /// CHECK: validated in the instruction against ``config.treasury``.
    /// Any account that matches the stored treasury pubkey is accepted
    /// as a lamport sink; the system-program transfer takes care of the
    /// actual balance update.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// On-chain record for one Vortex node.
#[account]
pub struct Peer {
    pub owner: Pubkey,
    pub node_pubkey: [u8; NODE_PUBKEY_LEN],
    pub endpoints: Vec<String>,
    pub metadata: String,
    pub registered_at: i64,
    pub last_heartbeat: i64,
    pub bump: u8,
    // ── Phase 7 fields ─────────────────────────────────────────────────
    /// SHA-256 of the signed INTEGRITY manifest the node is committed to.
    /// Meaningful once ``is_sealed == true``. Before that it's all zeros.
    pub code_hash: [u8; CODE_HASH_LEN],
    /// Once true, sealed forever — guards against undoing the initial pin.
    pub is_sealed: bool,
    /// Unix seconds when ``seal()`` was first called. 0 if never sealed.
    pub first_sealed_at: i64,
    /// Last successful ``checkin()`` or ``seal()``. Used by off-chain
    /// clients to compute a weight that decays with age.
    pub last_checkin: i64,
    // ── Phase A (treasury) fields ─────────────────────────────────────
    /// True once the owner has paid the on-chain register fee.
    pub fee_paid: bool,
    /// Unix seconds when the fee was paid (0 if never).
    pub fee_paid_at: i64,
}

impl Peer {
    pub fn space_for(endpoints: &[String], metadata: &str) -> usize {
        8  // anchor discriminator
        + 32                                  // owner
        + NODE_PUBKEY_LEN
        + 4 + endpoints.iter().map(|e| 4 + e.len()).sum::<usize>()
        + 4 + metadata.len()
        + 8                                   // registered_at
        + 8                                   // last_heartbeat
        + 1                                   // bump
        + CODE_HASH_LEN                       // code_hash
        + 1                                   // is_sealed
        + 8                                   // first_sealed_at
        + 8                                   // last_checkin
        + 1                                   // fee_paid
        + 8                                   // fee_paid_at
    }
}

/// Singleton program config stored at PDA ``["config"]``.
///
/// Holds mutable policy (treasury destination, current fee) plus
/// cumulative counters. Off-chain dashboards read these to display
/// lifetime inflow without scanning every peer account.
#[account]
pub struct Config {
    pub admin: Pubkey,
    pub treasury: Pubkey,
    pub register_fee_lamports: u64,
    pub total_fees_collected: u64,
    pub registrations_count: u64,
    pub bump: u8,
}

impl Config {
    pub const SIZE: usize = 8   // discriminator
        + 32  // admin
        + 32  // treasury
        + 8   // register_fee_lamports
        + 8   // total_fees_collected
        + 8   // registrations_count
        + 1;  // bump
}

#[event]
pub struct SealEvent {
    pub node_pubkey: [u8; NODE_PUBKEY_LEN],
    pub code_hash: [u8; CODE_HASH_LEN],
    pub at: i64,
}

#[event]
pub struct UpdatedEvent {
    pub node_pubkey: [u8; NODE_PUBKEY_LEN],
    pub old_hash: [u8; CODE_HASH_LEN],
    pub new_hash: [u8; CODE_HASH_LEN],
    pub at: i64,
}

#[event]
pub struct RegisterFeePaid {
    pub node_pubkey: [u8; NODE_PUBKEY_LEN],
    pub owner: Pubkey,
    pub treasury: Pubkey,
    pub amount_lamports: u64,
    pub at: i64,
}

#[error_code]
pub enum VortexError {
    #[msg("endpoints list must not be empty")]
    EmptyEndpoints,
    #[msg("too many endpoints (max 8)")]
    TooManyEndpoints,
    #[msg("individual endpoint must not be empty")]
    EmptyEndpoint,
    #[msg("endpoint too long (max 256 bytes)")]
    EndpointTooLong,
    #[msg("metadata too long (max 512 bytes)")]
    MetadataTooLong,
    #[msg("signer is not the peer account owner")]
    NotOwner,
    #[msg("node is already sealed — re-sealing is forbidden")]
    AlreadySealed,
    #[msg("node has not been sealed yet — seal() must be called first")]
    NotSealed,
    #[msg("supplied treasury account does not match the one in config")]
    WrongTreasury,
    #[msg("register fee exceeds the hard-coded safety cap (10 SOL)")]
    FeeAboveCap,
}
