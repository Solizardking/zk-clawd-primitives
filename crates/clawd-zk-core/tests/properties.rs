use clawd_zk_core::*;
use proptest::prelude::*;

proptest! {
    // Rust mirror of Lean `decode_preimage`.
    #[test]
    fn roundtrip(s in proptest::collection::vec(any::<u8>(), 0..80),
                 c in proptest::collection::vec(any::<u8>(), 0..80),
                 k in any::<u64>()) {
        let p = nullifier_preimage(&s, &c, k).unwrap();
        prop_assert_eq!(decode_preimage(&p), Some((&s[..], &c[..], k)));
    }

    // Rust mirror of Lean `preimage_injective`.
    #[test]
    fn injective(s in proptest::collection::vec(any::<u8>(), 0..8), c in proptest::collection::vec(any::<u8>(), 0..8), k in 0u64..4,
                 s2 in proptest::collection::vec(any::<u8>(), 0..8), c2 in proptest::collection::vec(any::<u8>(), 0..8), k2 in 0u64..4) {
        if (&s, &c, k) != (&s2, &c2, k2) {
            prop_assert_ne!(nullifier_preimage(&s, &c, k).unwrap(), nullifier_preimage(&s2, &c2, k2).unwrap());
        }
    }

    #[test]
    fn split_is_canonical_and_lossless(x in any::<[u8; 32]>()) {
        let [hi, lo] = split128(&x);
        prop_assert!(is_canonical_scalar(&hi) && is_canonical_scalar(&lo));
        prop_assert_eq!([&hi[16..], &lo[16..]].concat(), x.to_vec());
    }
}

#[test]
fn legacy_collides() {
    // Lean `legacy_not_injective`.
    assert_eq!(legacy_preimage(&[1, 2], &[3], &[]), legacy_preimage(&[1], &[2, 3], &[]));
    assert_ne!(nullifier_preimage(&[1, 2], &[3], 0), nullifier_preimage(&[1], &[2, 3], 0));
}

#[test]
fn legacy_nonce_encodings_alias() {
    // TS batch path appends u32le(i); the numeric path appends u64le(n).
    // secret‖ctx‖u64le(1) == secret‖(ctx‖01 00 00 00)‖u32le(0): another collision.
    let secret = [9u8; 16];
    let a = legacy_preimage(&secret, b"ctx", &1u64.to_le_bytes());
    let b = legacy_preimage(&secret, b"ctx\x01\x00\x00\x00", &0u32.to_le_bytes());
    assert_eq!(a, b);
}

#[test]
fn raw_bytes_are_often_not_canonical() {
    assert!(!is_canonical_scalar(&[0xff; 32]));
    assert!(!is_canonical_scalar(&BN254_R_BE));
    let mut r_minus_1 = BN254_R_BE;
    r_minus_1[31] -= 1;
    assert!(is_canonical_scalar(&r_minus_1));
}

#[test]
fn public_input_layouts() {
    let p = publish_public_inputs(&[1; 32], &[2; 32], &[3; 32], &[0xff; 32]);
    assert_eq!(p.len(), PUBLISH_NR_INPUTS);
    assert!(p.iter().all(is_canonical_scalar));
    assert_eq!(&p[6][16..], &[0xff; 16]);
    let c = consume_public_inputs(&[0xff; 32], &[5; 32], &[6; 32]);
    assert!(c.iter().all(is_canonical_scalar));
    let m = commit_public_inputs(&[0xff; 32], &[2; 32], &[3; 32], u64::MAX);
    assert!(m.iter().all(is_canonical_scalar));
    assert_eq!(&m[6][24..], &u64::MAX.to_be_bytes());
    assert_eq!(&m[6][..24], &[0u8; 24]);
}

#[test]
fn nullifier_secret_floor() {
    assert_eq!(compute_nullifier(&[0; 15], b"x", 0), Err(CoreError::SecretTooShort));
    assert_ne!(compute_nullifier(&[0; 16], b"x", 0).unwrap(), compute_nullifier(&[0; 16], b"x", 1).unwrap());
}
