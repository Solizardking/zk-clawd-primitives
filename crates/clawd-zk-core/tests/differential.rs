//! Differential test against the Lean spec. `formal/vectors/nullifier_v1.txt`
//! is produced by `lake exe vectors` (see scripts/check-formal.sh, which regenerates
//! it and fails on drift).
use clawd_zk_core::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn matches_lean_vectors() {
    let text = include_str!("../../../formal/vectors/nullifier_v1.txt");
    let mut n = 0;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 4, "bad vector line: {line}");
        let (s, c, k, want) = (unhex(f[0]), unhex(f[1]), f[2].parse::<u64>().unwrap(), unhex(f[3]));
        assert_eq!(nullifier_preimage(&s, &c, k).unwrap(), want);
        assert_eq!(decode_preimage(&want), Some((&s[..], &c[..], k)));
        n += 1;
    }
    assert_eq!(n, 3);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Public-input vectors shared with the TS client (`client/test/vectors.test.ts`).
/// Regenerate with `UPDATE_VECTORS=1 cargo test -p clawd-zk-core`.
#[test]
fn public_input_vectors() {
    let a = [0xfe; 32];
    let m: [u8; 32] = core::array::from_fn(|i| i as u8);
    let p = [0x30; 32];
    let n = compute_nullifier(&[7u8; 32], b"model-attest:v1:abc", 0).unwrap();
    let join = |v: &[[u8; 32]]| v.iter().map(|x| hex(x)).collect::<Vec<_>>().join(",");
    let got = format!(
        "nullifier {}\npublish {}\nconsume {}\ncommit {}\n",
        hex(&n),
        join(&publish_public_inputs(&a, &m, &p, &n)),
        join(&consume_public_inputs(&a, &m, &[0xff; 32])),
        join(&commit_public_inputs(&a, &m, &p, 0x0102030405060708)),
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../formal/vectors/public_inputs_v1.txt");
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(path, &got).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).expect("run with UPDATE_VECTORS=1 once"), got);
}
