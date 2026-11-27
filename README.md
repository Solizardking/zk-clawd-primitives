# 🦞🔐 Clawd ZK Primitives

> **A zero-knowledge primitive layer for Solana-native AI models.**
> Built on [Light Protocol](https://www.zkcompression.com).
> Powers the on-chain identity, attestation, and encrypted-state
> layer for the Clawd agent fleet.

## Implementation status

Phase 1 (2026-11-26): the program builds for SBF (`cargo build-sbf`,
Anchor 0.31.1 + light-sdk 0.17.1 + groth16-solana 0.3.1), Groth16 verifying
keys are **pinned in the program** (callers can no longer supply one),
instruction data is Borsh, and nullifiers / public inputs come from the
shared `crates/clawd-zk-core` crate, whose encoding is proved in Lean 4
(`formal/lean`) and cross-checked against Rust and TypeScript through
`formal/vectors`.

**Not deployable yet:** no production circuits exist, so every verifying-key
slot in `programs/clawd-zk/src/vk.rs` is empty and all three instructions
fail closed with `VerifyingKeyNotPinned`. The Light RPC wiring in the client
has not been run against a Light test validator. For an executable
off-chain workflow today, use the
[Model Kit artifact handoff](docs/INTEGRATION.md#model-kit-artifact-handoff).

## What this is

A focused, audited-friendly on-chain program plus a TypeScript SDK
that together provide three ZK primitives the rest of the Clawd
model stack relies on:

1. **Nullifier registry** — a 32-byte, deterministic, per-action hash
   that proves an action was taken exactly once. Stored as a
   compressed PDA (15,000 lamports per nullifier vs. 890,880 for a
   regular PDA). Used for: anti-double-publish, anti-double-claim,
   anti-double-inference-reward.

2. **Groth16 proof verification** — on-chain verifier for the
   bn128 / alt-bn128 zk-SNARK (~200k CU). Used for: model inference
   correctness, encrypted-state commitment, license-bound action
   authorization, ZK identity.

3. **Compressed state via Light Protocol** — model metadata,
   attestation records, and encrypted parameters live in
   rent-free compressed accounts in 26-deep (V1) or 32-deep (V2)
   state trees. Reads via Helius Photon; writes via CPI to the
   Light System Program.

The architecture is documented in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md).
The reasoning, cost analysis, and security model are all there.
The edge install and metadata handoff is documented in
[`docs/EDGE_DISTRIBUTION.md`](./docs/EDGE_DISTRIBUTION.md).

## Repo layout

```
zk-clawd-primitives/
├── Cargo.toml                    ← Rust workspace (program + core)
├── .cargo/config.toml            ← MSRV-aware resolver (platform-tools cargo 1.84)
├── crates/clawd-zk-core/         ← pure no_std core shared by program and client spec:
│                                    v1 nullifier encoding, split128 BN254 inputs
├── programs/clawd-zk/            ← Anchor program
│   └── src/
│       ├── lib.rs                ← instructions (publish / consume / commit)
│       ├── state.rs              ← compressed records + pure consume validation
│       ├── verify.rs             ← groth16-solana wrapper
│       └── vk.rs                 ← pinned verifying keys (empty = fail closed)
│   └── tests/                    ← groth16 (real proofs), consume rules, Borsh vectors
├── client/                       ← TypeScript SDK (@clawd/zk-client)
│   ├── src/encoding.ts           ← Borsh instruction encoders
│   ├── src/nullifier.ts          ← v1 nullifier (mirrors clawd-zk-core)
│   ├── src/proof.ts              ← split128 public inputs
│   └── test/                     ← unit tests + cross-implementation vectors
├── formal/
│   ├── lean/                     ← Lean 4 proofs (injectivity, BN254 limb split)
│   └── vectors/                  ← Lean/Rust-generated vectors all impls must match
├── agent/                        ← ZK Shark agent CLI
└── scripts/check-formal.sh       ← Lean → vectors → Rust → TS in one run
```

## The three instructions

```text
publish_attestation(validity_proof, address_tree_info, output_tree, offset,
                    {model_hash, payload_commitment, nullifier, allowed_consumer, groth16})
   ├── Groth16 vs PUBLISH_VK over split128(attester, model_hash, payload_commitment, nullifier)
   └── one Light CPI: create nullifier account [clawd-zk-nullifier, nullifier]
                      + AttestationAccount   [clawd-zk-attest, nullifier]

consume_attestation(validity_proof, account_meta, offset, record, consume_nonce, groth16)
   ├── validate record: active, nonce ≠ 0, consumer == allowed_consumer (if set)
   ├── Groth16 vs CONSUME_VK over split128(consumer, record address, consume_nonce)
   └── Light CPI: spend the current record (validity proof binds `record` to the
       leaf), write it back with status=consumed, consumed_by, consume_nonce

commit_encrypted_state(validity_proof, address_tree_info, output_tree, offset,
                       {model_hash, ciphertext_commitment, state_version, groth16})
   ├── Groth16 vs COMMIT_VK over split128(committer, model_hash, commitment) ‖ version
   └── Light CPI: create EncryptedStateAccount [clawd-zk-state, model, committer, version]
```

Proof bytes use groth16-solana's layout (uncompressed, big-endian, `a` = −A).

## Quick start

### Install

```bash
# Install the on-chain deps
cd programs/clawd-zk
cargo build-sbf

# Install the client SDK
cd ../../client
pnpm install   # or npm install
```

### Use the SDK

```ts
import { ClawdZkClient, computeNullifier } from "@clawd/zk-client";
import { createSolanaRpc, createKeyPairSignerFromBytes } from "@solana/kit";

const rpc = createSolanaRpc("https://mainnet.helius-rpc.com?api-key=...");
const signer = await createKeyPairSignerFromBytes(secretKey);
const client = new ClawdZkClient({ rpc, programId: PROGRAM_ID });

// 1. Compute the nullifier.
const nullifier = await computeNullifier({
  secret: signer.secretKey,
  context: "model-attestation:abc123",
});

// 2. Build the publish-attestation instruction.
//    (The Groth16 proof is generated off-chain and supplied by the caller.)
const ix = await client.publishAttestation({
  signer: signer.address,
  modelHash: hexToBytes("ab12..."),
  payloadCommitment: hexToBytes("cd34..."),
  nullifier,
  proof: { a: negA, b, c }, // no verifying key: the program pins it
});

// 3. Send.
const sig = await sendAndConfirm([ix], signer);
console.log("attestation published:", sig);
```

### Test

```bash
./scripts/check-formal.sh        # Lean proofs + vectors + all Rust + client tests
cargo test --workspace           # Rust only
(cd programs/clawd-zk && cargo build-sbf)
(cd client && npx vitest run)
(cd client && npx tsc -p . && cd ../agent && npx vitest run)   # agent needs client/dist
```

## Why this matters for the Clawd stack

The `ai-training/` pipeline produces fine-tuned models. The
`clawd-zk` primitive gives those models a verifiable on-chain
footprint:

- **Provenance**: every published inference or attestation gets a
  nullifier, so the same model can't claim the same reward twice.
- **Confidentiality**: weights and training data can be committed
  in encrypted form, with the proof attesting the committer's
  authority to publish.
- **Portability**: a Clawd agent on any chain, on any device, can
  read a model's attestation by querying the Helius Photon indexer
  with a single `getCompressedAccount` call.

This is the missing layer between "we trained a model" and "we
have provable, on-chain, sovereign identity for that model."

## Cloudflare edge metadata

The installer Worker in [`../cloudflare/`](../cloudflare/) advertises this ZK
surface through read-only JSON endpoints:

```bash
curl -fsSL https://install.onchainai.fund/.well-known/clawdbot-zk.json
curl -fsSL https://zk.x402.wtf/clawdbot/.well-known/clawdbot-zk.json
```

Those endpoints expose package names, operation names, docs, and trust gates.
They do not execute proofs or submit transactions. Installed runtimes continue
to discover local source through `CLAWDBOT_ZK_PRIMITIVES_DIR` and
`clawdbot catalog zk`.

## Status

Done in Phase 1: SBF build, pinned-VK verification, shared core, Borsh
client, real consume validation, real tests (Groth16 proofs generated and
verified on the host, Borsh golden vectors shared with the TS client, Lean
vectors shared by Lean, Rust and TS).

Still required before any deployment:

1. Write the three circuits (publish: knowledge of the nullifier secret;
   consume: consumer authorization; commit: plaintext knowledge), run a
   real multi-party setup, and pin the keys in `vk.rs`.
2. Integration tests on `light test-validator` / `light-program-test`
   (needs the Light prover server) for the CPI paths.
3. A program keypair for `4vJ9JU1b…` (or `anchor keys sync` to a new ID)
   and an explicit deploy decision.

## Historical Lineage

This ZK primitive layer is the Solana-native descendant of the
**PiedPiper project** (`docs/PiedPiper-master/`, from
[vs666/MinMax](https://github.com/vs666/MinMax)) — a landmark
academic implementation of classical compression (Huffman,
Arithmetic, BWT+RLE), encryption (AES-128, DES, RSA,
cellular-automaton-based PRNG), Conway's Game of Life, distributed
multi-agent collision avoidance, and cryptographic hash optimization.

The full adaptation mapping lives at
**[`docs/PIEDPIPER_ADAPTATION.md`](./docs/PIEDPIPER_ADAPTATION.md)**.
Every classical algorithm has an on-chain ZK equivalent:

| Classical Algorithm | ZK Primitive | On-Chain Instruction |
|---|---|---|
| Huffman/Arithmetic compression | `verifyGroth16` (proof of correct decompression) | `publish_attestation` |
| AES-128 / DES / RSA encryption | `commit_encrypted_state` (ciphertext commitment) | `commit_encrypted_state` |
| CA-based PRNG (PP_HASH) | `computeNullifier` (deterministic 32-byte hash) | Client-side derivation |
| CA-based SSH protocol | Nullifier-based session authentication | `publish_attestation` |
| Conway's Game of Life | Groth16 proof of universal computation | `publish_attestation` |
| Min-Max decision tree | `computeNullifier` for commitment schemes | Client-side |

For Huffman and Arithmetic, the verifier is Groth16 — the same
algorithm, now expressed as a pairing check on alt-bn128. For
AES-128, DES, and RSA, the ciphertext commitment is an on-chain
hash with a Groth16 proof that the committer knows the plaintext.
For PP_HASH, the nullifier is the direct ZK analogue of a
cellular-automaton pseudorandom function. For Conway's Game of
Life, the universal computer is provable through Groth16.

From Huffman to Groth16 — the same compression, the same encryption,
the same computation. Just faster. Just provable on Solana.

Credits:

- **Varul Srivastava** (`@vs666`) — primary author of MinMax, PP_HASH,
  PP_SSH, CA encryption, multi-agent collision avoidance, Game of Life,
  Forest Fire, PCA, Universal Computer document
- **Akshett Rai Jindal**, **Ashwin Mittal**, **Zishan Kazi**,
  **Keshav Bansal** — AES-128, DES, Huffman, Arithmetic, BWT+RLE,
  image compression, audio compression, video compression

Original repository: `https://github.com/vs666/MinMax`

## See also

- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — the deep dive
- [`docs/INTEGRATION.md`](./docs/INTEGRATION.md) — runtime catalog integration
- [`docs/EDGE_DISTRIBUTION.md`](./docs/EDGE_DISTRIBUTION.md) — Cloudflare install and metadata surface
- [`docs/PIEDPIPER_ADAPTATION.md`](./docs/PIEDPIPER_ADAPTATION.md) — classical→ZK algorithm map
- [`../ai-training/README.md`](../ai-training/README.md) — the model
  training pipeline that produces the weights this primitive attests to
- [`../AGENTS.md`](../AGENTS.md) — the Clawd agent catalog
- [Light Protocol docs](https://www.zkcompression.com) — the
  underlying ZK compression framework
- [light-verifier](https://docs.rs/light-verifier) — the on-chain
  Groth16 verifier we use
- [Helius Photon](https://docs.helius.dev) — the indexer that
  serves compressed-state reads

## License

Apache-2.0. The on-chain program and the TypeScript SDK are both
under Apache-2.0. The Light Protocol dependencies retain their
upstream licenses.
