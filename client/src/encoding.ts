/**
 * Borsh encoding of `clawd-zk` instruction data (Anchor layout:
 * 8-byte `sha256("global:<ix_name>")` discriminator, then the Borsh args).
 *
 * Mirrors `programs/clawd-zk/src/lib.rs`. `test/vectors.test.ts` checks
 * every encoder byte-for-byte against `formal/vectors/borsh_ix_v1.txt`,
 * which the Rust program's own test regenerates from the real types.
 */

import { createHash } from "node:crypto";

export interface CompressedProof {
  a: Uint8Array; // 32
  b: Uint8Array; // 64
  c: Uint8Array; // 32
}

/** Light `ValidityProof(Option<CompressedProof>)`. */
export type LightValidityProof = CompressedProof | null;

export interface PackedAddressTreeInfoArgs {
  addressMerkleTreePubkeyIndex: number;
  addressQueuePubkeyIndex: number;
  rootIndex: number;
}

export interface PackedStateTreeInfoArgs {
  rootIndex: number;
  proveByIndex: boolean;
  merkleTreePubkeyIndex: number;
  queuePubkeyIndex: number;
  leafIndex: number;
}

export interface CompressedAccountMetaArgs {
  treeInfo: PackedStateTreeInfoArgs;
  address: Uint8Array; // 32
  outputStateTreeIndex: number;
}

/** groth16-solana layout: big-endian, `a` already negated. */
export interface Groth16ProofBytes {
  a: Uint8Array; // 64
  b: Uint8Array; // 128
  c: Uint8Array; // 64
}

export interface AttestationRecord {
  modelHash: Uint8Array;
  attester: Uint8Array;
  payloadCommitment: Uint8Array;
  nullifier: Uint8Array;
  /** All zeros = anyone may consume. */
  allowedConsumer: Uint8Array;
  publishedAt: bigint;
  status: number;
  consumedBy: Uint8Array;
  consumeNonce: Uint8Array;
}

export interface PublishAttestationIx {
  proof: LightValidityProof;
  addressTreeInfo: PackedAddressTreeInfoArgs;
  outputStateTreeIndex: number;
  systemAccountsOffset: number;
  args: {
    modelHash: Uint8Array;
    payloadCommitment: Uint8Array;
    nullifier: Uint8Array;
    allowedConsumer: Uint8Array;
    groth16: Groth16ProofBytes;
  };
}

export interface ConsumeAttestationIx {
  proof: LightValidityProof;
  accountMeta: CompressedAccountMetaArgs;
  systemAccountsOffset: number;
  record: AttestationRecord;
  consumeNonce: Uint8Array;
  groth16: Groth16ProofBytes;
}

export interface CommitEncryptedStateIx {
  proof: LightValidityProof;
  addressTreeInfo: PackedAddressTreeInfoArgs;
  outputStateTreeIndex: number;
  systemAccountsOffset: number;
  args: {
    modelHash: Uint8Array;
    ciphertextCommitment: Uint8Array;
    stateVersion: bigint | number;
    groth16: Groth16ProofBytes;
  };
}

class Writer {
  private parts: number[] = [];
  fixed(b: Uint8Array, len: number, name: string): this {
    if (b.length !== len) throw new Error(`${name}: expected ${len} bytes, got ${b.length}`);
    for (const x of b) this.parts.push(x);
    return this;
  }
  u8(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new Error(`u8 out of range: ${n}`);
    this.parts.push(n);
    return this;
  }
  bool(b: boolean): this {
    return this.u8(b ? 1 : 0);
  }
  uint(n: bigint | number, bytes: number, signed = false): this {
    let v = BigInt(n);
    const bits = BigInt(bytes * 8);
    const min = signed ? -(1n << (bits - 1n)) : 0n;
    const max = signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n;
    if (v < min || v > max) throw new Error(`integer out of range for ${bytes} bytes: ${n}`);
    if (v < 0n) v += 1n << bits;
    for (let i = 0; i < bytes; i++) {
      this.parts.push(Number(v & 0xffn));
      v >>= 8n;
    }
    return this;
  }
  bytes(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

export function discriminator(ixName: string): Uint8Array {
  return createHash("sha256").update(`global:${ixName}`).digest().subarray(0, 8);
}

function validity(w: Writer, p: LightValidityProof) {
  if (p === null) return w.u8(0);
  return w.u8(1).fixed(p.a, 32, "proof.a").fixed(p.b, 64, "proof.b").fixed(p.c, 32, "proof.c");
}

function addressTree(w: Writer, t: PackedAddressTreeInfoArgs) {
  w.u8(t.addressMerkleTreePubkeyIndex).u8(t.addressQueuePubkeyIndex).uint(t.rootIndex, 2);
}

function groth16(w: Writer, g: Groth16ProofBytes) {
  w.fixed(g.a, 64, "groth16.a").fixed(g.b, 128, "groth16.b").fixed(g.c, 64, "groth16.c");
}

export function encodePublishAttestation(ix: PublishAttestationIx): Uint8Array {
  const w = new Writer().fixed(discriminator("publish_attestation"), 8, "disc");
  validity(w, ix.proof);
  addressTree(w, ix.addressTreeInfo);
  w.u8(ix.outputStateTreeIndex).u8(ix.systemAccountsOffset);
  const a = ix.args;
  w.fixed(a.modelHash, 32, "modelHash")
    .fixed(a.payloadCommitment, 32, "payloadCommitment")
    .fixed(a.nullifier, 32, "nullifier")
    .fixed(a.allowedConsumer, 32, "allowedConsumer");
  groth16(w, a.groth16);
  return w.bytes();
}

function encodeAttestationRecord(w: Writer, r: AttestationRecord) {
  w.fixed(r.modelHash, 32, "record.modelHash")
    .fixed(r.attester, 32, "record.attester")
    .fixed(r.payloadCommitment, 32, "record.payloadCommitment")
    .fixed(r.nullifier, 32, "record.nullifier")
    .fixed(r.allowedConsumer, 32, "record.allowedConsumer")
    .uint(r.publishedAt, 8, true)
    .u8(r.status)
    .fixed(r.consumedBy, 32, "record.consumedBy")
    .fixed(r.consumeNonce, 32, "record.consumeNonce");
}

export function encodeConsumeAttestation(ix: ConsumeAttestationIx): Uint8Array {
  const w = new Writer().fixed(discriminator("consume_attestation"), 8, "disc");
  validity(w, ix.proof);
  const t = ix.accountMeta.treeInfo;
  w.uint(t.rootIndex, 2).bool(t.proveByIndex).u8(t.merkleTreePubkeyIndex).u8(t.queuePubkeyIndex).uint(t.leafIndex, 4);
  w.fixed(ix.accountMeta.address, 32, "accountMeta.address").u8(ix.accountMeta.outputStateTreeIndex);
  w.u8(ix.systemAccountsOffset);
  encodeAttestationRecord(w, ix.record);
  w.fixed(ix.consumeNonce, 32, "consumeNonce");
  groth16(w, ix.groth16);
  return w.bytes();
}

export function encodeCommitEncryptedState(ix: CommitEncryptedStateIx): Uint8Array {
  const w = new Writer().fixed(discriminator("commit_encrypted_state"), 8, "disc");
  validity(w, ix.proof);
  addressTree(w, ix.addressTreeInfo);
  w.u8(ix.outputStateTreeIndex).u8(ix.systemAccountsOffset);
  const a = ix.args;
  w.fixed(a.modelHash, 32, "modelHash").fixed(a.ciphertextCommitment, 32, "ciphertextCommitment").uint(a.stateVersion, 8);
  groth16(w, a.groth16);
  return w.bytes();
}
