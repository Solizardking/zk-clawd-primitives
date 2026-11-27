/**
 * Nullifier computation — v1, mirrors `crates/clawd-zk-core`.
 *
 *     nullifier = SHA-256( "clawd-zk-nullifier/v1"
 *                          ‖ u32le(|secret|)  ‖ secret
 *                          ‖ u32le(|context|) ‖ context
 *                          ‖ u64le(nonce) )
 *
 * The length prefixes and domain tag make the encoding injective (proved
 * in Lean: `formal/lean/ClawdZk/Nullifier.lean`, `preimage_injective`),
 * so two different (secret, context, nonce) triples can only collide
 * through a SHA-256 collision. The previous construction,
 * `sha256(secret ‖ context ‖ nonce)`, was not injective and is removed.
 * `test/vectors.test.ts` checks this file against the Lean-generated vectors.
 */

import { createHash } from "node:crypto";
import type { PublicKey } from "@solana/web3.js";
import type { Bytes32 } from "./types.js";

export interface NullifierInputs {
  /** 16+ bytes of secret material (e.g. a derived signing subkey). */
  secret: Uint8Array;
  /** Context tag (e.g. "model-attest:v1:<model_hash>"). */
  context: Uint8Array | string;
  /** u64 nonce; defaults to 0. */
  nonce?: bigint | number;
}

export const NULLIFIER_DOMAIN_V1 = new TextEncoder().encode("clawd-zk-nullifier/v1");

const U32_MAX = 0xffff_ffff;
const U64_MAX = (1n << 64n) - 1n;

function lenPrefixed(field: Uint8Array): Uint8Array {
  if (field.length > U32_MAX) throw new Error("field longer than u32::MAX bytes");
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, true);
  out.set(field, 4);
  return out;
}

/** The exact bytes that are hashed. Matches `clawd_zk_core::nullifier_preimage`. */
export function nullifierPreimage(
  secret: Uint8Array,
  context: Uint8Array | string,
  nonce: bigint | number = 0,
): Uint8Array {
  const ctx = typeof context === "string" ? new TextEncoder().encode(context) : context;
  const n = BigInt(nonce);
  if (n < 0n || n > U64_MAX) throw new Error("nonce must fit in u64");
  const nonceBytes = new Uint8Array(8);
  new DataView(nonceBytes.buffer).setBigUint64(0, n, true);
  const parts = [NULLIFIER_DOMAIN_V1, lenPrefixed(secret), lenPrefixed(ctx), nonceBytes];
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Deterministic 32-byte nullifier. Matches `clawd_zk_core::compute_nullifier`. */
export async function computeNullifier(inputs: NullifierInputs): Promise<Bytes32> {
  if (inputs.secret.length < 16) {
    throw new Error("Nullifier secret must be at least 16 bytes.");
  }
  const pre = nullifierPreimage(inputs.secret, inputs.context, inputs.nonce ?? 0);
  return new Uint8Array(createHash("sha256").update(pre).digest()) as Bytes32;
}

/** N nullifiers for one (secret, context), nonces 0..count-1. */
export async function computeNullifierBatch(
  baseInputs: Omit<NullifierInputs, "nonce">,
  count: number,
): Promise<Bytes32[]> {
  const out: Bytes32[] = [];
  for (let i = 0; i < count; i++) {
    out.push(await computeNullifier({ ...baseInputs, nonce: BigInt(i) }));
  }
  return out;
}

/** On-chain address seed prefixes (`programs/clawd-zk/src/state.rs`). */
export const NULLIFIER_PREFIX = new TextEncoder().encode("clawd-zk-nullifier");
export const ATTESTATION_PREFIX = new TextEncoder().encode("clawd-zk-attest");
export const STATE_PREFIX = new TextEncoder().encode("clawd-zk-state");

async function deriveV2(seeds: Uint8Array[], addressTree: PublicKey, programId: PublicKey) {
  const sdk: any = await import("@lightprotocol/stateless.js");
  const seed = sdk.deriveAddressSeedV2(seeds);
  const address = sdk.deriveAddressV2(seed, addressTree, programId);
  return { address, seed };
}

/** Address of the nullifier account (`[NULLIFIER_PREFIX, nullifier]`, v2 tree). */
export function deriveNullifierAddress(programId: PublicKey, addressTree: PublicKey, nullifier: Bytes32) {
  return deriveV2([NULLIFIER_PREFIX, nullifier], addressTree, programId);
}

/** Address of the attestation record (`[ATTESTATION_PREFIX, nullifier]`, v2 tree). */
export function deriveAttestationAddress(programId: PublicKey, addressTree: PublicKey, nullifier: Bytes32) {
  return deriveV2([ATTESTATION_PREFIX, nullifier], addressTree, programId);
}
