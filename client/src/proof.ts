/**
 * Groth16 public inputs and proof bytes — mirrors `crates/clawd-zk-core`.
 *
 * Every 32-byte value (pubkey, hash, nullifier, nonce) becomes TWO BN254
 * scalars: its high and low 128 bits, each as a 32-byte big-endian field
 * element. Raw 32-byte values are frequently ≥ the BN254 modulus r, so they
 * cannot be passed as scalars directly. The split is proved canonical and
 * lossless in Lean (`formal/lean/ClawdZk/Field.lean`).
 *
 * The verifying key is pinned in the program; it is never sent.
 */

import type { Groth16Proof, Bytes32 } from "./types.js";

export const PUBLISH_NR_INPUTS = 8;
export const CONSUME_NR_INPUTS = 6;
export const COMMIT_NR_INPUTS = 7;

/** BN254 scalar modulus r, big-endian. */
export const BN254_R_BE = Uint8Array.from(
  Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex"),
);

export function isCanonicalScalar(be: Uint8Array): boolean {
  if (be.length !== 32) return false;
  for (let i = 0; i < 32; i++) {
    if (be[i] !== BN254_R_BE[i]) return be[i] < BN254_R_BE[i];
  }
  return false; // equal to r
}

/** Split a 32-byte big-endian value into [hi, lo] 128-bit limbs. */
export function split128(be: Uint8Array): [Bytes32, Bytes32] {
  if (be.length !== 32) throw new Error(`expected 32 bytes, got ${be.length}`);
  const hi = new Uint8Array(32);
  const lo = new Uint8Array(32);
  hi.set(be.subarray(0, 16), 16);
  lo.set(be.subarray(16), 16);
  return [hi as Bytes32, lo as Bytes32];
}

function limbs(values: Uint8Array[]): Bytes32[] {
  return values.flatMap((v) => split128(v));
}

export interface PublishAttestationPublicInputs {
  attester: Uint8Array;
  modelHash: Uint8Array;
  payloadCommitment: Uint8Array;
  nullifier: Uint8Array;
}

export interface ConsumeAttestationPublicInputs {
  consumer: Uint8Array;
  attestationAddress: Uint8Array;
  consumeNonce: Uint8Array;
}

export interface CommitStatePublicInputs {
  committer: Uint8Array;
  modelHash: Uint8Array;
  ciphertextCommitment: Uint8Array;
  stateVersion: bigint | number;
}

/** Matches `clawd_zk_core::publish_public_inputs` (8 scalars). */
export function buildPublishPublicInputs(p: PublishAttestationPublicInputs): Bytes32[] {
  return limbs([p.attester, p.modelHash, p.payloadCommitment, p.nullifier]);
}

/** Matches `clawd_zk_core::consume_public_inputs` (6 scalars). */
export function buildConsumePublicInputs(p: ConsumeAttestationPublicInputs): Bytes32[] {
  return limbs([p.consumer, p.attestationAddress, p.consumeNonce]);
}

/** Matches `clawd_zk_core::commit_public_inputs` (7 scalars; version big-endian in the last 8 bytes). */
export function buildCommitPublicInputs(p: CommitStatePublicInputs): Bytes32[] {
  const v = BigInt(p.stateVersion);
  if (v < 0n || v >= 1n << 64n) throw new Error("stateVersion must fit in u64");
  const version = new Uint8Array(32);
  new DataView(version.buffer).setBigUint64(24, v, false);
  return [...limbs([p.committer, p.modelHash, p.ciphertextCommitment]), version as Bytes32];
}

/** Concatenate scalars (e.g. for a prover's input file). */
export function packPublicInputs(inputs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(inputs.length * 32);
  inputs.forEach((chunk, i) => {
    if (chunk.length !== 32) {
      throw new Error(`Public input #${i} must be exactly 32 bytes (got ${chunk.length}).`);
    }
    out.set(chunk, i * 32);
  });
  return out;
}

/** Validate proof point sizes (groth16-solana layout: BE, `a` negated). */
export function serializeProof(p: Groth16Proof): { a: Uint8Array; b: Uint8Array; c: Uint8Array } {
  validatePoint(p.a, 64, "proof.a");
  validatePoint(p.b, 128, "proof.b");
  validatePoint(p.c, 64, "proof.c");
  return { a: p.a, b: p.b, c: p.c };
}

function validatePoint(p: Uint8Array, expected: number, name: string) {
  if (p.length !== expected) {
    throw new Error(`Invalid ${name}: expected ${expected} bytes, got ${p.length}.`);
  }
}

/**
 * Off-chain shape check before sending: proof sizes, input count, and
 * every input a canonical scalar. The pairing check runs on-chain.
 */
export function verifyGroth16Offchain(args: {
  proof: Groth16Proof;
  publicInputs: Uint8Array[];
  expectedInputs?: number;
}): { ok: boolean; reason?: string } {
  if (args.publicInputs.length < 1) return { ok: false, reason: "public inputs cannot be empty" };
  if (args.expectedInputs !== undefined && args.publicInputs.length !== args.expectedInputs) {
    return { ok: false, reason: `expected ${args.expectedInputs} public inputs, got ${args.publicInputs.length}` };
  }
  const bad = args.publicInputs.findIndex((x) => !isCanonicalScalar(x));
  if (bad >= 0) return { ok: false, reason: `public input #${bad} is not a canonical BN254 scalar` };
  try {
    serializeProof(args.proof);
  } catch (e: any) {
    return { ok: false, reason: e.message };
  }
  return { ok: true };
}
