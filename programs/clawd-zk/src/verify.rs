//! Groth16 verification against a pinned key (groth16-solana, alt_bn128
//! syscalls on-chain, arkworks fallback on the host).

use crate::{vk::PinnedVk, ClawdZkError};
use anchor_lang::prelude::*;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

/// Uncompressed Groth16 proof, big-endian, in groth16-solana's layout.
/// `a` must already be negated (−A), as groth16-solana expects.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Groth16Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

/// Verify `proof` for `public_inputs` against a specific key.
pub fn verify_with_key<const N: usize>(
    vk: &Groth16Verifyingkey,
    proof: &Groth16Proof,
    public_inputs: &[[u8; 32]; N],
) -> Result<()> {
    let mut verifier = Groth16Verifier::new(&proof.a, &proof.b, &proof.c, public_inputs, vk)
        .map_err(|_| error!(ClawdZkError::InvalidProof))?;
    verifier.verify().map_err(|_| error!(ClawdZkError::InvalidProof))?;
    Ok(())
}

/// Verify against a pinned slot; fails closed if the slot is empty.
pub fn verify_pinned<const N: usize>(
    vk: PinnedVk,
    proof: &Groth16Proof,
    public_inputs: &[[u8; 32]; N],
) -> Result<()> {
    let vk = vk.ok_or_else(|| error!(ClawdZkError::VerifyingKeyNotPinned))?;
    verify_with_key(vk, proof, public_inputs)
}
