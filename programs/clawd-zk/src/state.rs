//! Compressed account records and the pure validation rules applied to
//! them. Validation is kept free of Light/Anchor runtime calls so it is
//! unit-tested on the host (and is a future Lean/Aeneas target).

use crate::ClawdZkError;
use anchor_lang::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use light_sdk::LightDiscriminator;

pub const NULLIFIER_SEED: &[u8] = b"clawd-zk-nullifier";
pub const ATTESTATION_SEED: &[u8] = b"clawd-zk-attest";
pub const STATE_SEED: &[u8] = b"clawd-zk-state";

pub const STATUS_ACTIVE: u8 = 0;
pub const STATUS_CONSUMED: u8 = 1;

/// Empty by design: existence at the derived address *is* the nullifier.
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize, LightDiscriminator)]
pub struct NullifierAccount {}

/// Published model attestation. The client passes the current record
/// back in `consume_attestation`; Light's validity proof fails unless the
/// record hashes to the leaf owned by this program at that address, so a
/// forged record cannot be consumed.
#[derive(Clone, Debug, Default, PartialEq, Eq, AnchorSerialize, AnchorDeserialize, LightDiscriminator)]
pub struct AttestationAccount {
    pub model_hash: [u8; 32],
    pub attester: Pubkey,
    pub payload_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    /// `Pubkey::default()` = any consumer may consume.
    pub allowed_consumer: Pubkey,
    pub published_at: i64,
    pub status: u8,
    pub consumed_by: Pubkey,
    pub consume_nonce: [u8; 32],
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize, LightDiscriminator)]
pub struct EncryptedStateAccount {
    pub model_hash: [u8; 32],
    pub committer: Pubkey,
    pub ciphertext_commitment: [u8; 32],
    pub version: u64,
    pub published_at: i64,
}

/// Rules for consuming an attestation. Pure: no syscalls, no CPI.
pub fn validate_consume(
    record: &AttestationAccount,
    consumer: &Pubkey,
    consume_nonce: &[u8; 32],
) -> core::result::Result<(), ClawdZkError> {
    if record.status != STATUS_ACTIVE {
        return Err(ClawdZkError::AttestationNotActive);
    }
    if record.consume_nonce != [0u8; 32] || record.consumed_by != Pubkey::default() {
        return Err(ClawdZkError::AttestationNotActive);
    }
    if *consume_nonce == [0u8; 32] {
        return Err(ClawdZkError::InvalidConsumeNonce);
    }
    if record.allowed_consumer != Pubkey::default() && record.allowed_consumer != *consumer {
        return Err(ClawdZkError::ConsumerNotAllowed);
    }
    Ok(())
}

/// The record after a successful consume.
pub fn consumed(mut record: AttestationAccount, consumer: &Pubkey, consume_nonce: &[u8; 32]) -> AttestationAccount {
    record.status = STATUS_CONSUMED;
    record.consumed_by = *consumer;
    record.consume_nonce = *consume_nonce;
    record
}

/// Address seed for an encrypted-state record: one record per
/// (model, committer, version), so a version cannot be committed twice.
pub fn state_seed_version(version: u64) -> [u8; 8] {
    version.to_le_bytes()
}
