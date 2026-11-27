//! # Clawd ZK Primitive
//!
//! On-chain program that provides ZK primitives for the Solana Clawd AI
//! model stack. Uses Light Protocol for compressed state (~67M leaves per
//! state tree, 15k lamports per compressed nullifier).
//!
//! ## Capabilities
//!
//! 1. **Nullifier registry** — prevent double-publish / double-claim of
//!    AI model attestations. A nullifier is derived from a (secret, context)
//!    pair, and its on-chain existence proves the action was taken once.
//!
//! 2. **Groth16 proof verification** — verify a Groth16 zk-SNARK that
//!    attests to model inference correctness, encrypted state commitment,
//!    or any other relation the agent produces off-chain.
//!
//! 3. **Compressed state** — model metadata, attestation records, and
//!    encrypted parameters live in Light Protocol state trees (rent-free,
//!    ~5k lamports per tree per tx).
//!
//! 4. **Encrypted state** — opaque ciphertext blobs are committed in
//!    compressed accounts. Decryption happens off-chain with a key derived
//!    from the Groth16 proof's private inputs.
//!
//! ## Architecture
//!
//! ```text
//!   ┌──────────┐      ┌────────────────┐      ┌──────────────┐
//!   │  Agent   │─────▶│  Clawd ZK      │─────▶│ Light System │
//!   │ (off-chain) │  ①│  Program       │  ③  │ Program      │
//!   │          │      │  (verifies +   │      │ (CPI: tree   │
//!   │ ②  ──────│─────▶│   cpi's null)  │      │  updates)    │
//!   │ Groth16  │      └────────────────┘      └──────────────┘
//!   │ proof    │                │                       │
//!   └──────────┘                ▼                       ▼
//!                       ┌────────────────┐      ┌──────────────┐
//!                       │ Photon Indexer │◀─────│ State Trees  │
//!                       │  (RPC read)    │      │  (Merkle)    │
//!                       └────────────────┘      └──────────────┘
//! ```
//!
//! ① Agent sends the nullifier, a Groth16 proof and Borsh instruction data
//! ② The program re-derives the public inputs (clawd-zk-core: two 128-bit
//!    limbs per 32-byte value) and verifies the proof against a verifying
//!    key pinned in `vk.rs` — callers cannot supply a key
//! ③ Program CPIs the Light System Program (one validity proof per
//!    instruction) to create/update compressed accounts

#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
use light_sdk::{
    account::LightAccount,
    address::v2::derive_address,
    cpi::{v2::CpiAccounts, v2::LightSystemProgramCpi, InvokeLightSystemProgram, LightCpiInstruction},
    derive_light_cpi_signer,
    instruction::{account_meta::CompressedAccountMeta, PackedAddressTreeInfo, ValidityProof},
};
use light_sdk_types::CpiSigner;

pub mod state;
pub mod verify;
pub mod vk;

use state::{AttestationAccount, EncryptedStateAccount, NullifierAccount};
use verify::{verify_pinned, Groth16Proof};

// Matches the ID the client and agent already use. Not deployed anywhere
// (checked devnet + mainnet 2026-11-26); deploying needs its keypair or
// `anchor keys sync` with a new one.
declare_id!("4vJ9JU1bJJE96FWSVKmnrL3xFU5jSBSVdk9x4La2vzhn");

pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("4vJ9JU1bJJE96FWSVKmnrL3xFU5jSBSVdk9x4La2vzhn");

#[program]
pub mod clawd_zk {
    use super::*;

    /// Publish a model attestation exactly once. Creates (atomically, in
    /// one Light CPI) a nullifier account at `[NULLIFIER_SEED, nullifier]`
    /// and the attestation record at `[ATTESTATION_SEED, nullifier]`.
    /// Re-using the nullifier fails because the address already exists.
    pub fn publish_attestation<'info>(
        ctx: Context<'_, '_, '_, 'info, SignerAccounts<'info>>,
        proof: ValidityProof,
        address_tree_info: PackedAddressTreeInfo,
        output_state_tree_index: u8,
        system_accounts_offset: u8,
        args: PublishArgs,
    ) -> Result<()> {
        let attester = ctx.accounts.signer.key();
        let inputs = clawd_zk_core::publish_public_inputs(
            &attester.to_bytes(),
            &args.model_hash,
            &args.payload_commitment,
            &args.nullifier,
        );
        verify_pinned(vk::PUBLISH_VK, &args.groth16, &inputs)?;

        let cpi_accounts = light_cpi_accounts(ctx.accounts.signer.as_ref(), ctx.remaining_accounts, system_accounts_offset)?;
        let tree = address_tree(&address_tree_info, &cpi_accounts)?;

        let (nullifier_address, nullifier_seed) =
            derive_address(&[state::NULLIFIER_SEED, &args.nullifier], &tree, &crate::ID);
        let (record_address, record_seed) =
            derive_address(&[state::ATTESTATION_SEED, &args.nullifier], &tree, &crate::ID);

        let nullifier_account = LightAccount::<NullifierAccount>::new_init(
            &crate::ID,
            Some(nullifier_address),
            output_state_tree_index,
        );
        let mut record = LightAccount::<AttestationAccount>::new_init(
            &crate::ID,
            Some(record_address),
            output_state_tree_index,
        );
        *record = AttestationAccount {
            model_hash: args.model_hash,
            attester,
            payload_commitment: args.payload_commitment,
            nullifier: args.nullifier,
            allowed_consumer: args.allowed_consumer,
            published_at: Clock::get()?.unix_timestamp,
            status: state::STATUS_ACTIVE,
            consumed_by: Pubkey::default(),
            consume_nonce: [0u8; 32],
        };

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(nullifier_account)?
            .with_light_account(record)?
            .with_new_addresses(&[
                address_tree_info.into_new_address_params_assigned_packed(nullifier_seed, Some(0)),
                address_tree_info.into_new_address_params_assigned_packed(record_seed, Some(1)),
            ])
            .invoke(cpi_accounts)?;

        msg!("clawd-zk: published attestation by {}", attester);
        Ok(())
    }

    /// Consume an attestation once. The client passes the current record;
    /// the program validates it (active, nonce, allowed consumer), checks
    /// the consume proof, and writes the consumed record. Light's validity
    /// proof binds `record` to the existing leaf, and spending that leaf
    /// makes a second consume of the same state impossible.
    pub fn consume_attestation<'info>(
        ctx: Context<'_, '_, '_, 'info, SignerAccounts<'info>>,
        proof: ValidityProof,
        account_meta: CompressedAccountMeta,
        system_accounts_offset: u8,
        record: AttestationAccount,
        consume_nonce: [u8; 32],
        groth16: Groth16Proof,
    ) -> Result<()> {
        let consumer = ctx.accounts.signer.key();
        state::validate_consume(&record, &consumer, &consume_nonce)?;

        let inputs = clawd_zk_core::consume_public_inputs(
            &consumer.to_bytes(),
            &account_meta.address,
            &consume_nonce,
        );
        verify_pinned(vk::CONSUME_VK, &groth16, &inputs)?;

        let cpi_accounts = light_cpi_accounts(ctx.accounts.signer.as_ref(), ctx.remaining_accounts, system_accounts_offset)?;
        let mut account = LightAccount::<AttestationAccount>::new_mut(&crate::ID, &account_meta, record)?;
        let updated = state::consumed((*account).clone(), &consumer, &consume_nonce);
        *account = updated;

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(account)?
            .invoke(cpi_accounts)?;

        msg!("clawd-zk: attestation consumed by {}", consumer);
        Ok(())
    }

    /// Commit an encrypted-state commitment. One record per
    /// (model_hash, committer, version): the address is derived from all
    /// three, so the same version cannot be committed twice.
    pub fn commit_encrypted_state<'info>(
        ctx: Context<'_, '_, '_, 'info, SignerAccounts<'info>>,
        proof: ValidityProof,
        address_tree_info: PackedAddressTreeInfo,
        output_state_tree_index: u8,
        system_accounts_offset: u8,
        args: CommitArgs,
    ) -> Result<()> {
        let committer = ctx.accounts.signer.key();
        let inputs = clawd_zk_core::commit_public_inputs(
            &committer.to_bytes(),
            &args.model_hash,
            &args.ciphertext_commitment,
            args.state_version,
        );
        verify_pinned(vk::COMMIT_VK, &args.groth16, &inputs)?;

        let cpi_accounts = light_cpi_accounts(ctx.accounts.signer.as_ref(), ctx.remaining_accounts, system_accounts_offset)?;
        let tree = address_tree(&address_tree_info, &cpi_accounts)?;
        let version = state::state_seed_version(args.state_version);
        let (address, seed) = derive_address(
            &[state::STATE_SEED, &args.model_hash, committer.as_ref(), &version],
            &tree,
            &crate::ID,
        );
        let mut account = LightAccount::<EncryptedStateAccount>::new_init(
            &crate::ID,
            Some(address),
            output_state_tree_index,
        );
        *account = EncryptedStateAccount {
            model_hash: args.model_hash,
            committer,
            ciphertext_commitment: args.ciphertext_commitment,
            version: args.state_version,
            published_at: Clock::get()?.unix_timestamp,
        };

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(account)?
            .with_new_addresses(&[address_tree_info.into_new_address_params_assigned_packed(seed, Some(0))])
            .invoke(cpi_accounts)?;

        msg!("clawd-zk: committed encrypted state v{} by {}", args.state_version, committer);
        Ok(())
    }
}

fn light_cpi_accounts<'c, 'info>(
    signer: &'c AccountInfo<'info>,
    remaining_accounts: &'c [AccountInfo<'info>],
    system_accounts_offset: u8,
) -> Result<CpiAccounts<'c, 'info>> {
    let rest = remaining_accounts
        .get(system_accounts_offset as usize..)
        .ok_or_else(|| error!(ClawdZkError::NotEnoughAccounts))?;
    Ok(CpiAccounts::new(signer, rest, LIGHT_CPI_SIGNER))
}

fn address_tree(info: &PackedAddressTreeInfo, cpi_accounts: &CpiAccounts) -> Result<Pubkey> {
    let tree = info
        .get_tree_pubkey(cpi_accounts)
        .map_err(|_| error!(ClawdZkError::NotEnoughAccounts))?;
    require!(
        tree.to_bytes() == light_sdk::constants::ADDRESS_TREE_V2,
        ClawdZkError::UnknownTree
    );
    Ok(tree)
}

// ============================================================================
// Accounts + instruction data (Borsh via Anchor)
// ============================================================================

#[derive(Accounts)]
pub struct SignerAccounts<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct PublishArgs {
    pub model_hash: [u8; 32],
    pub payload_commitment: [u8; 32],
    /// v1 nullifier (`clawd_zk_core::compute_nullifier`).
    pub nullifier: [u8; 32],
    /// `Pubkey::default()` = anyone may consume.
    pub allowed_consumer: Pubkey,
    pub groth16: Groth16Proof,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct CommitArgs {
    pub model_hash: [u8; 32],
    pub ciphertext_commitment: [u8; 32],
    pub state_version: u64,
    pub groth16: Groth16Proof,
}

#[error_code]
#[derive(PartialEq, Eq)]
pub enum ClawdZkError {
    #[msg("The Groth16 proof did not verify against the pinned key and public inputs.")]
    InvalidProof,
    #[msg("No verifying key is pinned for this instruction; it is disabled.")]
    VerifyingKeyNotPinned,
    #[msg("The address tree is not Light's v2 address tree.")]
    UnknownTree,
    #[msg("Not enough remaining accounts for the Light CPI.")]
    NotEnoughAccounts,
    #[msg("The attestation is not active (already consumed or revoked).")]
    AttestationNotActive,
    #[msg("The consume nonce must be non-zero.")]
    InvalidConsumeNonce,
    #[msg("This attestation is restricted to a different consumer.")]
    ConsumerNotAllowed,
}
