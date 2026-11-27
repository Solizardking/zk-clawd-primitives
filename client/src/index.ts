/**
 * @clawd/zk-client
 *
 * TypeScript client SDK for the Clawd ZK primitive on Solana.
 *
 * The SDK wraps three things:
 *   1. **Nullifier computation** — deterministic hashes from a (secret, context) pair.
 *   2. **Groth16 proof assembly** — wire-format packing for on-chain verification.
 *   3. **Light Protocol integration** — fetching validity proofs from the
 *      Photon indexer, packing system accounts, building CPI-ready instructions.
 *
 * ## Quick start
 *
 * ```ts
 * import { ClawdZkClient, computeNullifier } from "@clawd/zk-client";
 *
 * const client = new ClawdZkClient({ rpc, programId });
 * const nullifier = await computeNullifier({ secret, context: "model-attest:v1:<hash>" });
 * const ix = await client.publishAttestation({
 *   signer, modelHash, payloadCommitment, nullifier,
 *   proof: { a: negA, b, c }, // groth16-solana layout; no verifying key
 * });
 * ```
 */

export * from "./nullifier.js";
export * from "./encoding.js";
export * from "./proof.js";
export * from "./state.js";
export * from "./client.js";
export * from "./types.js";
