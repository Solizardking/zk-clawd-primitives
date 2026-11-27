//! consume_attestation validation rules (pure; the Light CPI part is
//! covered by the validity proof and is exercised on a Light validator).
use anchor_lang::prelude::Pubkey;
use clawd_zk::state::*;
use clawd_zk::ClawdZkError;

fn active(allowed: Pubkey) -> AttestationAccount {
    AttestationAccount {
        model_hash: [1; 32],
        attester: Pubkey::new_from_array([2; 32]),
        payload_commitment: [3; 32],
        nullifier: [4; 32],
        allowed_consumer: allowed,
        published_at: 1_700_000_000,
        status: STATUS_ACTIVE,
        consumed_by: Pubkey::default(),
        consume_nonce: [0; 32],
    }
}

const ALICE: Pubkey = Pubkey::new_from_array([0xa1; 32]);
const BOB: Pubkey = Pubkey::new_from_array([0xb0; 32]);
const NONCE: [u8; 32] = [9; 32];

#[test]
fn open_attestation_consumable_by_anyone() {
    assert_eq!(validate_consume(&active(Pubkey::default()), &ALICE, &NONCE), Ok(()));
    assert_eq!(validate_consume(&active(Pubkey::default()), &BOB, &NONCE), Ok(()));
}

#[test]
fn restricted_attestation_checks_consumer() {
    assert_eq!(validate_consume(&active(ALICE), &ALICE, &NONCE), Ok(()));
    assert_eq!(validate_consume(&active(ALICE), &BOB, &NONCE), Err(ClawdZkError::ConsumerNotAllowed));
}

#[test]
fn zero_nonce_rejected() {
    assert_eq!(validate_consume(&active(ALICE), &ALICE, &[0; 32]), Err(ClawdZkError::InvalidConsumeNonce));
}

#[test]
fn consume_is_one_shot() {
    let after = consumed(active(Pubkey::default()), &ALICE, &NONCE);
    assert_eq!(after.status, STATUS_CONSUMED);
    assert_eq!(after.consumed_by, ALICE);
    assert_eq!(after.consume_nonce, NONCE);
    // Every other field is preserved.
    let mut expect = active(Pubkey::default());
    expect.status = STATUS_CONSUMED;
    expect.consumed_by = ALICE;
    expect.consume_nonce = NONCE;
    assert_eq!(after, expect);
    // A consumed record can never be consumed again, by anyone, with any nonce.
    for who in [ALICE, BOB] {
        assert_eq!(validate_consume(&after, &who, &[7; 32]), Err(ClawdZkError::AttestationNotActive));
    }
}

#[test]
fn inconsistent_active_record_rejected() {
    // status says active but consume fields are set: treat as not active.
    let mut r = active(Pubkey::default());
    r.consume_nonce = [1; 32];
    assert_eq!(validate_consume(&r, &ALICE, &NONCE), Err(ClawdZkError::AttestationNotActive));
    let mut r = active(Pubkey::default());
    r.status = 2; // revoked
    assert_eq!(validate_consume(&r, &ALICE, &NONCE), Err(ClawdZkError::AttestationNotActive));
}
