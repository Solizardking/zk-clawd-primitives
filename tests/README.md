# Tests

```bash
./scripts/check-formal.sh   # everything below in one run
```

| Where | What | How |
| --- | --- | --- |
| `formal/lean` | Lean 4 proofs: nullifier encoding injective, BN254 limb split canonical + lossless | `lake build` |
| `crates/clawd-zk-core/tests` | Lean vector match, proptest round-trip/injectivity, public-input vectors | `cargo test -p clawd-zk-core` |
| `programs/clawd-zk/tests/groth16.rs` | Real Groth16 proofs (throwaway arkworks setup) verified by the program's groth16-solana path; tampered proofs/inputs, relabelled attesters, wrong-circuit keys and empty pinned slots rejected | `cargo test -p clawd-zk` |
| `programs/clawd-zk/tests/consume.rs` | consume rules: active only, non-zero nonce, allowed consumer, one-shot | `cargo test -p clawd-zk` |
| `programs/clawd-zk/tests/borsh_vectors.rs` | Golden Borsh instruction data + Light v2 addresses (shared with TS) | `cargo test -p clawd-zk` |
| `client/test` | TS client against all vectors (Lean, Rust core, Rust program) + unit tests | `cd client && npx vitest run` |
| `agent/tests` | ZK Shark agent intents/CLI (mocked client) | `cd agent && npx vitest run` |
| `tests/test_model_attestation.py` | Model Kit digest handoff | `python3 -m unittest tests.test_model_attestation` |
| SBF build | `cargo build-sbf` (platform-tools v1.52) | `cd programs/clawd-zk && cargo build-sbf` |

Not covered yet: Light CPI paths on `light test-validator` /
`light-program-test` (needs the Light prover server).
## Edge Metadata Tests

```bash
cd ../..
node --test cloudflare/install-worker.test.mjs
```

This covers the Cloudflare Worker metadata, `/clawdbot` base path handling,
shell wrapper exports, and raw installer proxy headers.

## On-Chain Tests

```bash
cd programs/clawd-zk
cargo test-sbf
```

The Rust/SBF path needs a Light-compatible validator and configured state trees.
Use it for instruction-level behavior after deployment addresses are set.

## Test Boundaries

- Off-chain tests prove local packing/routing behavior.
- Edge metadata tests prove read-only install/ZK discovery behavior.
- On-chain tests prove Anchor instruction behavior and CPI boundaries.
- Neither test path should require private keys committed to this repo.
