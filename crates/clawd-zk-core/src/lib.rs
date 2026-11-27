//! Pure core of zk-clawd-primitives.
//!
//! Everything here is deterministic, allocation-light and free of Solana /
//! Anchor types so it can be (a) shared by the on-chain program and the
//! off-chain client, and (b) extracted to Lean with Aeneas later.
//! The Lean specification lives in `formal/lean/ClawdZk`;
//! `tests/differential.rs` checks this crate byte-for-byte against it.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Domain tag. Lean: `ClawdZk.domainTag`.
pub const NULLIFIER_DOMAIN_V1: &[u8] = b"clawd-zk-nullifier/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum CoreError {
    /// A field longer than `u32::MAX` bytes cannot be length-prefixed.
    FieldTooLong,
    /// Secret shorter than 16 bytes (same floor as the TS client).
    SecretTooShort,
}

fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8]) -> Result<(), CoreError> {
    let len = u32::try_from(field.len()).map_err(|_| CoreError::FieldTooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// v1 nullifier preimage:
/// `tag ‖ u32le(|secret|) ‖ secret ‖ u32le(|context|) ‖ context ‖ u64le(nonce)`.
/// Lean: `ClawdZk.preimage`; injectivity is `ClawdZk.preimage_injective`.
pub fn nullifier_preimage(secret: &[u8], context: &[u8], nonce: u64) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::with_capacity(NULLIFIER_DOMAIN_V1.len() + 16 + secret.len() + context.len());
    out.extend_from_slice(NULLIFIER_DOMAIN_V1);
    push_len_prefixed(&mut out, secret)?;
    push_len_prefixed(&mut out, context)?;
    out.extend_from_slice(&nonce.to_le_bytes());
    Ok(out)
}

/// Inverse of [`nullifier_preimage`]. Lean: `ClawdZk.decode`.
/// Returns `None` for any byte string that is not a well-formed preimage.
pub fn decode_preimage(bytes: &[u8]) -> Option<(&[u8], &[u8], u64)> {
    let body = bytes.strip_prefix(NULLIFIER_DOMAIN_V1)?;
    let (secret, rest) = read_field(body)?;
    let (context, rest) = read_field(rest)?;
    let nonce = u64::from_le_bytes(rest.try_into().ok()?);
    Some((secret, context, nonce))
}

fn read_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = u32::from_le_bytes(*len) as usize;
    (rest.len() >= len).then(|| rest.split_at(len))
}

/// `SHA-256(nullifier_preimage(..))`. Collision resistance of SHA-256 is an
/// assumption; given it, distinct inputs give distinct nullifiers.
pub fn compute_nullifier(secret: &[u8], context: &[u8], nonce: u64) -> Result<[u8; 32], CoreError> {
    if secret.len() < 16 {
        return Err(CoreError::SecretTooShort);
    }
    Ok(Sha256::digest(nullifier_preimage(secret, context, nonce)?).into())
}

/// The construction currently in `client/src/nullifier.ts`
/// (`sha256(secret ‖ context ‖ nonce)`). Kept only so tests can
/// demonstrate its collision (Lean: `ClawdZk.legacy_not_injective`).
pub fn legacy_preimage(secret: &[u8], context: &[u8], nonce: &[u8]) -> Vec<u8> {
    [secret, context, nonce].concat()
}

/// BN254 scalar modulus `r`, big-endian. Lean: `ClawdZk.bn254R`.
pub const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// True iff the big-endian 32-byte value is a canonical BN254 scalar (< r).
pub fn is_canonical_scalar(be: &[u8; 32]) -> bool {
    be < &BN254_R_BE // lexicographic order on big-endian bytes = numeric order
}

/// Split a 32-byte big-endian value into two canonical scalars (hi, lo),
/// each holding 128 bits, as 32-byte big-endian field elements.
/// Lean: `ClawdZk.split128` (`split128_canonical`, `split128_injective`).
pub fn split128(be: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&be[..16]);
    lo[16..].copy_from_slice(&be[16..]);
    [hi, lo]
}

/// Number of Groth16 public inputs for each instruction (two limbs per
/// 32-byte value, plus one scalar for the state version).
pub const PUBLISH_NR_INPUTS: usize = 8;
pub const CONSUME_NR_INPUTS: usize = 6;
pub const COMMIT_NR_INPUTS: usize = 7;

fn limbs<const N: usize>(values: &[&[u8; 32]]) -> [[u8; 32]; N] {
    debug_assert_eq!(values.len() * 2, N);
    let mut out = [[0u8; 32]; N];
    for (i, v) in values.iter().enumerate() {
        let [hi, lo] = split128(v);
        out[2 * i] = hi;
        out[2 * i + 1] = lo;
    }
    out
}

/// Public inputs for `publish_attestation`, in circuit order:
/// `split128(attester) ‖ split128(model_hash) ‖ split128(payload_commitment) ‖ split128(nullifier)`.
pub fn publish_public_inputs(
    attester: &[u8; 32],
    model_hash: &[u8; 32],
    payload_commitment: &[u8; 32],
    nullifier: &[u8; 32],
) -> [[u8; 32]; PUBLISH_NR_INPUTS] {
    limbs(&[attester, model_hash, payload_commitment, nullifier])
}

/// Public inputs for `consume_attestation`:
/// `split128(consumer) ‖ split128(attestation_address) ‖ split128(consume_nonce)`.
pub fn consume_public_inputs(
    consumer: &[u8; 32],
    attestation_address: &[u8; 32],
    consume_nonce: &[u8; 32],
) -> [[u8; 32]; CONSUME_NR_INPUTS] {
    limbs(&[consumer, attestation_address, consume_nonce])
}

/// Public inputs for `commit_encrypted_state`:
/// `split128(committer) ‖ split128(model_hash) ‖ split128(ciphertext_commitment) ‖ be(version)`.
pub fn commit_public_inputs(
    committer: &[u8; 32],
    model_hash: &[u8; 32],
    ciphertext_commitment: &[u8; 32],
    state_version: u64,
) -> [[u8; 32]; COMMIT_NR_INPUTS] {
    let six: [[u8; 32]; 6] = limbs(&[committer, model_hash, ciphertext_commitment]);
    let mut out = [[0u8; 32]; COMMIT_NR_INPUTS];
    out[..6].copy_from_slice(&six);
    out[6][24..].copy_from_slice(&state_version.to_be_bytes());
    out
}
