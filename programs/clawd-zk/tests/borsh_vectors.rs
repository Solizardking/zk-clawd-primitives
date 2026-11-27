//! Golden Borsh instruction-data vectors shared with the TS client
//! (`client/src/encoding.test.ts` re-encodes the same values and must match).
//! Regenerate with `UPDATE_VECTORS=1 cargo test -p clawd-zk --test borsh_vectors`.
use anchor_lang::{prelude::Pubkey, InstructionData};
use clawd_zk::state::AttestationAccount;
use clawd_zk::verify::Groth16Proof;
use clawd_zk::{instruction, CommitArgs, PublishArgs};
use light_sdk::instruction::{
    account_meta::CompressedAccountMeta, PackedAddressTreeInfo, PackedStateTreeInfo, ValidityProof,
};
use light_sdk::instruction::CompressedProof;
use light_sdk::address::v2::derive_address;

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn g16() -> Groth16Proof {
    Groth16Proof { a: seq(0x10), b: seq(0x50), c: seq(0xd0) }
}

fn validity() -> ValidityProof {
    ValidityProof(Some(CompressedProof { a: seq(1), b: seq(33), c: seq(97) }))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vectors() -> String {
    let tree = PackedAddressTreeInfo { address_merkle_tree_pubkey_index: 1, address_queue_pubkey_index: 2, root_index: 0x0304 };
    let publish = instruction::PublishAttestation {
        proof: validity(),
        address_tree_info: tree,
        output_state_tree_index: 5,
        system_accounts_offset: 6,
        args: PublishArgs {
            model_hash: [0x11; 32],
            payload_commitment: [0x22; 32],
            nullifier: [0x33; 32],
            allowed_consumer: Pubkey::new_from_array([0x44; 32]),
            groth16: g16(),
        },
    }
    .data();
    let consume = instruction::ConsumeAttestation {
        proof: ValidityProof(None),
        account_meta: CompressedAccountMeta {
            tree_info: PackedStateTreeInfo { root_index: 7, prove_by_index: true, merkle_tree_pubkey_index: 8, queue_pubkey_index: 9, leaf_index: 0x0a0b0c0d },
            address: [0x55; 32],
            output_state_tree_index: 10,
        },
        system_accounts_offset: 0,
        record: AttestationAccount {
            model_hash: [0x11; 32],
            attester: Pubkey::new_from_array([0x66; 32]),
            payload_commitment: [0x22; 32],
            nullifier: [0x33; 32],
            allowed_consumer: Pubkey::default(),
            published_at: -2,
            status: 0,
            consumed_by: Pubkey::default(),
            consume_nonce: [0; 32],
        },
        consume_nonce: [0x77; 32],
        groth16: g16(),
    }
    .data();
    let commit = instruction::CommitEncryptedState {
        proof: validity(),
        address_tree_info: tree,
        output_state_tree_index: 1,
        system_accounts_offset: 2,
        args: CommitArgs { model_hash: [0x11; 32], ciphertext_commitment: [0x88; 32], state_version: 0x0102030405060708, groth16: g16() },
    }
    .data();
    // Address derivation (Light v2) for the seeds the program uses, against
    // the real v2 address tree, so the TS client can check it derives the same.
    let tree = Pubkey::new_from_array(light_sdk::constants::ADDRESS_TREE_V2);
    let nf = [0x33u8; 32];
    let (nf_addr, _) = derive_address(&[clawd_zk::state::NULLIFIER_SEED, &nf], &tree, &clawd_zk::ID);
    let (rec_addr, _) = derive_address(&[clawd_zk::state::ATTESTATION_SEED, &nf], &tree, &clawd_zk::ID);
    format!(
        "publish_attestation {}\nconsume_attestation {}\ncommit_encrypted_state {}\nprogram_id {}\naddress_tree_v2 {}\nnullifier_address {}\nattestation_address {}\n",
        hex(&publish), hex(&consume), hex(&commit), clawd_zk::ID, tree, hex(&nf_addr), hex(&rec_addr)
    )
}

#[test]
fn borsh_vectors_match() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../formal/vectors/borsh_ix_v1.txt");
    let got = vectors();
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(path, &got).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).expect("run with UPDATE_VECTORS=1 once"), got);
}
