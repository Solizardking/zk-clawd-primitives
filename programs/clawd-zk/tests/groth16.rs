//! Real Groth16 tests for the program's verification path.
//!
//! Generates a throwaway (INSECURE, test-only) setup with arkworks for a
//! circuit whose public inputs are exactly the instruction's packed inputs,
//! proves, converts to groth16-solana's byte layout, and checks that the
//! program's `verify_with_key` accepts honest proofs and rejects tampered
//! proofs, tampered inputs, relabelled attesters and wrong-sized keys.
//! The pinned slots are also checked to fail closed.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_relations::lc;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use clawd_zk::verify::{verify_pinned, verify_with_key, Groth16Proof};
use clawd_zk::{vk, ClawdZkError};
use clawd_zk_core::*;
use groth16_solana::groth16::Groth16Verifyingkey;

/// Circuit: one witness per public input, constrained equal to it.
#[derive(Clone)]
struct Echo(Vec<Fr>);

impl ConstraintSynthesizer<Fr> for Echo {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for v in self.0 {
            let x = cs.new_input_variable(|| Ok(v))?;
            let w = cs.new_witness_variable(|| Ok(v))?;
            cs.enforce_r1cs_constraint(|| lc![w], || lc![Variable::One], || lc![x])?;
        }
        Ok(())
    }
}

fn be_chunks<const CHUNK: usize, const N: usize>(le: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, c) in le[..N].chunks(CHUNK).enumerate() {
        let mut r = c.to_vec();
        r.reverse();
        out[i * CHUNK..(i + 1) * CHUNK].copy_from_slice(&r);
    }
    out
}

fn g1(p: &G1Affine) -> [u8; 64] {
    let mut buf = Vec::new();
    p.serialize_with_mode(&mut buf, Compress::No).unwrap();
    be_chunks::<32, 64>(&buf)
}

fn g2(p: &G2Affine) -> [u8; 128] {
    let mut buf = Vec::new();
    p.serialize_with_mode(&mut buf, Compress::No).unwrap();
    be_chunks::<64, 128>(&buf)
}

fn to_fr(limbs: &[[u8; 32]]) -> Vec<Fr> {
    limbs.iter().map(|l| Fr::from_be_bytes_mod_order(l)).collect()
}

struct Setup {
    pk: ProvingKey<Bn254>,
    vk: Groth16Verifyingkey<'static>,
}

fn setup(nr_inputs: usize) -> Setup {
    let mut rng = StdRng::seed_from_u64(0xc1a3d);
    let (pk, avk) =
        Groth16::<Bn254>::circuit_specific_setup(Echo(vec![Fr::from(0u64); nr_inputs]), &mut rng).unwrap();
    let ic: Vec<[u8; 64]> = avk.gamma_abc_g1.iter().map(g1).collect();
    let vk = Groth16Verifyingkey {
        nr_pubinputs: nr_inputs,
        vk_alpha_g1: g1(&avk.alpha_g1),
        vk_beta_g2: g2(&avk.beta_g2),
        vk_gamma_g2: g2(&avk.gamma_g2),
        vk_delta_g2: g2(&avk.delta_g2),
        vk_ic: Box::leak(ic.into_boxed_slice()),
        vk_commitment: None,
    };
    Setup { pk, vk }
}

fn prove(s: &Setup, limbs: &[[u8; 32]]) -> Groth16Proof {
    let mut rng = StdRng::seed_from_u64(0xc1a3d);
    let p = Groth16::<Bn254>::prove(&s.pk, Echo(to_fr(limbs)), &mut rng).unwrap();
    let neg_a: G1Affine = (-p.a.into_group()).into();
    Groth16Proof { a: g1(&neg_a), b: g2(&p.b), c: g1(&p.c) }
}

fn is_invalid_proof(r: anchor_lang::Result<()>) -> bool {
    match r {
        Err(anchor_lang::error::Error::AnchorError(e)) => {
            e.error_code_number == anchor_lang::error::ERROR_CODE_OFFSET + ClawdZkError::InvalidProof as u32
        }
        _ => false,
    }
}

const ATTESTER: [u8; 32] = [0xfe; 32]; // > r as raw bytes; fine as limbs
const MODEL: [u8; 32] = [0x11; 32];
const PAYLOAD: [u8; 32] = [0x22; 32];

#[test]
fn publish_honest_proof_verifies() {
    let s = setup(PUBLISH_NR_INPUTS);
    let nf = compute_nullifier(&[7u8; 32], b"model-attest:v1:abc", 0).unwrap();
    let inputs = publish_public_inputs(&ATTESTER, &MODEL, &PAYLOAD, &nf);
    let proof = prove(&s, &inputs);
    verify_with_key(&s.vk, &proof, &inputs).expect("honest proof must verify");
}

#[test]
fn publish_rejects_relabelled_inputs() {
    let s = setup(PUBLISH_NR_INPUTS);
    let nf = compute_nullifier(&[7u8; 32], b"ctx", 0).unwrap();
    let inputs = publish_public_inputs(&ATTESTER, &MODEL, &PAYLOAD, &nf);
    let proof = prove(&s, &inputs);
    // Different attester (front-running the proof), different nullifier,
    // different model: all must be rejected.
    let other_nf = compute_nullifier(&[7u8; 32], b"ctx", 1).unwrap();
    for bad in [
        publish_public_inputs(&[0x01; 32], &MODEL, &PAYLOAD, &nf),
        publish_public_inputs(&ATTESTER, &MODEL, &PAYLOAD, &other_nf),
        publish_public_inputs(&ATTESTER, &[0x12; 32], &PAYLOAD, &nf),
    ] {
        assert!(is_invalid_proof(verify_with_key(&s.vk, &proof, &bad)));
    }
}

#[test]
fn rejects_tampered_proof_points() {
    let s = setup(CONSUME_NR_INPUTS);
    let inputs = consume_public_inputs(&[3; 32], &[4; 32], &[5; 32]);
    let good = prove(&s, &inputs);
    verify_with_key(&s.vk, &good, &inputs).unwrap();
    let mut bad = good.clone();
    bad.c[63] ^= 1;
    assert!(is_invalid_proof(verify_with_key(&s.vk, &bad, &inputs)));
    // Forgetting to negate A (groth16-solana wants -A) must not verify.
    let mut unneg = good.clone();
    unneg.a = groth16_solana::groth16::negate_g1_be(&good.a);
    assert!(is_invalid_proof(verify_with_key(&s.vk, &unneg, &inputs)));
    // Garbage that is not a curve point is rejected, not a panic.
    let mut junk = good;
    junk.b = [0xff; 128];
    assert!(is_invalid_proof(verify_with_key(&s.vk, &junk, &inputs)));
}

#[test]
fn commit_binds_version() {
    let s = setup(COMMIT_NR_INPUTS);
    let inputs = commit_public_inputs(&[9; 32], &MODEL, &[8; 32], 42);
    let proof = prove(&s, &inputs);
    verify_with_key(&s.vk, &proof, &inputs).unwrap();
    let wrong = commit_public_inputs(&[9; 32], &MODEL, &[8; 32], 43);
    assert!(is_invalid_proof(verify_with_key(&s.vk, &proof, &wrong)));
}

#[test]
fn key_for_another_circuit_is_rejected() {
    // A consume-shaped key cannot be used to verify publish inputs.
    let s = setup(CONSUME_NR_INPUTS);
    let inputs = publish_public_inputs(&ATTESTER, &MODEL, &PAYLOAD, &[1; 32]);
    let proof = prove(&setup(PUBLISH_NR_INPUTS), &inputs);
    assert!(is_invalid_proof(verify_with_key(&s.vk, &proof, &inputs)));
}

#[test]
fn unpinned_slots_fail_closed() {
    let s = setup(PUBLISH_NR_INPUTS);
    let inputs = publish_public_inputs(&ATTESTER, &MODEL, &PAYLOAD, &[1; 32]);
    let proof = prove(&s, &inputs);
    // Production slots are empty until real circuits + a real setup exist.
    assert!(vk::PUBLISH_VK.is_none() && vk::CONSUME_VK.is_none() && vk::COMMIT_VK.is_none());
    match verify_pinned(vk::PUBLISH_VK, &proof, &inputs) {
        Err(anchor_lang::error::Error::AnchorError(e)) => assert_eq!(
            e.error_code_number,
            anchor_lang::error::ERROR_CODE_OFFSET + ClawdZkError::VerifyingKeyNotPinned as u32
        ),
        other => panic!("expected VerifyingKeyNotPinned, got {other:?}"),
    }
    // Pinning a correctly shaped key makes the same proof verify.
    let pinned: &'static Groth16Verifyingkey<'static> = Box::leak(Box::new(s.vk));
    assert!(vk::vk_shape_matches(pinned, PUBLISH_NR_INPUTS));
    verify_pinned(Some(pinned), &proof, &inputs).unwrap();
}
