//! Pinned Groth16 verifying keys — one per instruction.
//!
//! Callers can no longer supply a verifying key (that made every proof
//! forgeable: pick your own circuit, prove anything). The program only
//! accepts proofs against the constants below.
//!
//! **No production circuits exist yet**, so every slot is `None` and the
//! corresponding instruction fails closed with `VerifyingKeyNotPinned`.
//! To pin a key once a circuit and a real (multi-party) setup exist:
//!
//! ```text
//! // build.rs or a one-off tool, groth16-solana = { version = "=0.3.1", features = ["circom-vk"] }
//! groth16_solana::vk::circom::generate_vk_file(
//!     "circuits/publish/verification_key.json", "src/vk/", "publish_vk.rs",
//!     SetupKind::Trusted, ProvingKeySource::File("publish.zkey"))
//! ```
//!
//! then replace `None` with `Some(&publish_vk::VERIFYINGKEY)`. The public
//! input count of each circuit MUST equal the `*_NR_INPUTS` constant in
//! `clawd-zk-core`; `vk_shape_matches` below enforces it in tests. Never
//! pin an `InsecureTest` setup (groth16-solana emits a `compile_error!`
//! for it unless an `insecure-test-setup` feature is enabled).

use clawd_zk_core::{COMMIT_NR_INPUTS, CONSUME_NR_INPUTS, PUBLISH_NR_INPUTS};
use groth16_solana::groth16::Groth16Verifyingkey;

pub type PinnedVk = Option<&'static Groth16Verifyingkey<'static>>;

pub const PUBLISH_VK: PinnedVk = None;
pub const CONSUME_VK: PinnedVk = None;
pub const COMMIT_VK: PinnedVk = None;

/// True iff `vk` is shaped for a circuit with `nr_inputs` public inputs.
pub fn vk_shape_matches(vk: &Groth16Verifyingkey, nr_inputs: usize) -> bool {
    vk.vk_ic.len() == nr_inputs + 1 && vk.vk_commitment.is_none()
}

pub const EXPECTED_INPUTS: [(&str, usize); 3] = [
    ("publish", PUBLISH_NR_INPUTS),
    ("consume", CONSUME_NR_INPUTS),
    ("commit", COMMIT_NR_INPUTS),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_slots_are_shaped_or_empty() {
        for ((name, n), vk) in EXPECTED_INPUTS.iter().zip([PUBLISH_VK, CONSUME_VK, COMMIT_VK]) {
            if let Some(vk) = vk {
                assert!(vk_shape_matches(vk, *n), "{name} vk has wrong input count");
            }
        }
    }
}
