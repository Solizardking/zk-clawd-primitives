/**
 * Cross-implementation vectors. Every file under formal/vectors is produced
 * by Lean (nullifier_v1.txt) or by the Rust program/core tests
 * (borsh_ix_v1.txt, public_inputs_v1.txt); the TS client must agree byte for byte.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PublicKey } from "@solana/web3.js";
import {
  computeNullifier,
  deriveAttestationAddress,
  deriveNullifierAddress,
  nullifierPreimage,
} from "../src/nullifier.js";
import { buildCommitPublicInputs, buildConsumePublicInputs, buildPublishPublicInputs } from "../src/proof.js";
import {
  encodeCommitEncryptedState,
  encodeConsumeAttestation,
  encodePublishAttestation,
  type Groth16ProofBytes,
  type LightValidityProof,
} from "../src/encoding.js";
import { CLAWD_ZK_PROGRAM_ID } from "../src/client.js";
import type { Bytes32 } from "../src/types.js";

const dir = fileURLToPath(new URL("../../formal/vectors/", import.meta.url));
const read = (f: string) => readFileSync(dir + f, "utf8").trim().split("\n");
const kv = (f: string) => Object.fromEntries(read(f).map((l) => l.split(" ") as [string, string]));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const seq = (n: number, start: number) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

describe("nullifier v1 vs Lean spec", () => {
  const lines = read("nullifier_v1.txt");
  it("has the Lean vectors", () => expect(lines.length).toBe(3));
  for (const line of lines) {
    const [s, c, k, want] = line.split(" ");
    it(`preimage matches Lean for nonce ${k}`, () => {
      expect(hex(nullifierPreimage(unhex(s), unhex(c), BigInt(k)))).toBe(want);
    });
  }
  it("nullifier hash matches Rust core", async () => {
    const n = await computeNullifier({ secret: fill(32, 7), context: "model-attest:v1:abc", nonce: 0 });
    expect(hex(n)).toBe(kv("public_inputs_v1.txt").nullifier);
    expect(hex(n)).toBe(
      hex(createHash("sha256").update(nullifierPreimage(fill(32, 7), "model-attest:v1:abc", 0)).digest()),
    );
  });
});

describe("public inputs vs Rust core", () => {
  const v = kv("public_inputs_v1.txt");
  const a = fill(32, 0xfe);
  const m = seq(32, 0);
  const p = fill(32, 0x30);
  const join = (xs: Uint8Array[]) => xs.map(hex).join(",");
  it("publish", () => {
    expect(join(buildPublishPublicInputs({ attester: a, modelHash: m, payloadCommitment: p, nullifier: unhex(v.nullifier) }))).toBe(v.publish);
  });
  it("consume", () => {
    expect(join(buildConsumePublicInputs({ consumer: a, attestationAddress: m, consumeNonce: fill(32, 0xff) }))).toBe(v.consume);
  });
  it("commit", () => {
    expect(join(buildCommitPublicInputs({ committer: a, modelHash: m, ciphertextCommitment: p, stateVersion: 0x0102030405060708n }))).toBe(v.commit);
  });
});

describe("Borsh instruction data vs Rust program", () => {
  const v = kv("borsh_ix_v1.txt");
  const g16: Groth16ProofBytes = { a: seq(64, 0x10), b: seq(128, 0x50), c: seq(64, 0xd0) };
  const validity: LightValidityProof = { a: seq(32, 1), b: seq(64, 33), c: seq(32, 97) };
  const tree = { addressMerkleTreePubkeyIndex: 1, addressQueuePubkeyIndex: 2, rootIndex: 0x0304 };

  it("publish_attestation", () => {
    const data = encodePublishAttestation({
      proof: validity,
      addressTreeInfo: tree,
      outputStateTreeIndex: 5,
      systemAccountsOffset: 6,
      args: { modelHash: fill(32, 0x11), payloadCommitment: fill(32, 0x22), nullifier: fill(32, 0x33), allowedConsumer: fill(32, 0x44), groth16: g16 },
    });
    expect(hex(data)).toBe(v.publish_attestation);
  });

  it("consume_attestation", () => {
    const data = encodeConsumeAttestation({
      proof: null,
      accountMeta: {
        treeInfo: { rootIndex: 7, proveByIndex: true, merkleTreePubkeyIndex: 8, queuePubkeyIndex: 9, leafIndex: 0x0a0b0c0d },
        address: fill(32, 0x55),
        outputStateTreeIndex: 10,
      },
      systemAccountsOffset: 0,
      record: {
        modelHash: fill(32, 0x11),
        attester: fill(32, 0x66),
        payloadCommitment: fill(32, 0x22),
        nullifier: fill(32, 0x33),
        allowedConsumer: fill(32, 0),
        publishedAt: -2n,
        status: 0,
        consumedBy: fill(32, 0),
        consumeNonce: fill(32, 0),
      },
      consumeNonce: fill(32, 0x77),
      groth16: g16,
    });
    expect(hex(data)).toBe(v.consume_attestation);
  });

  it("commit_encrypted_state", () => {
    const data = encodeCommitEncryptedState({
      proof: validity,
      addressTreeInfo: tree,
      outputStateTreeIndex: 1,
      systemAccountsOffset: 2,
      args: { modelHash: fill(32, 0x11), ciphertextCommitment: fill(32, 0x88), stateVersion: 0x0102030405060708n, groth16: g16 },
    });
    expect(hex(data)).toBe(v.commit_encrypted_state);
  });

  it("program id and Light v2 address derivation match the program", async () => {
    expect(CLAWD_ZK_PROGRAM_ID.toBase58()).toBe(v.program_id);
    const tree = new PublicKey(v.address_tree_v2);
    const nf = fill(32, 0x33) as Bytes32;
    const { address: a1 } = await deriveNullifierAddress(CLAWD_ZK_PROGRAM_ID, tree, nf);
    const { address: a2 } = await deriveAttestationAddress(CLAWD_ZK_PROGRAM_ID, tree, nf);
    expect(hex(a1.toBytes())).toBe(v.nullifier_address);
    expect(hex(a2.toBytes())).toBe(v.attestation_address);
  });

  it("rejects wrong-sized fields and out-of-range integers", () => {
    const bad = { ...g16, a: new Uint8Array(63) };
    expect(() =>
      encodeCommitEncryptedState({ proof: null, addressTreeInfo: tree, outputStateTreeIndex: 0, systemAccountsOffset: 0, args: { modelHash: fill(32, 0), ciphertextCommitment: fill(32, 0), stateVersion: 1n, groth16: bad } }),
    ).toThrow(/groth16\.a/);
    expect(() =>
      encodeCommitEncryptedState({ proof: null, addressTreeInfo: tree, outputStateTreeIndex: 256, systemAccountsOffset: 0, args: { modelHash: fill(32, 0), ciphertextCommitment: fill(32, 0), stateVersion: 1n, groth16: g16 } }),
    ).toThrow(/u8/);
    expect(() =>
      encodeCommitEncryptedState({ proof: null, addressTreeInfo: tree, outputStateTreeIndex: 0, systemAccountsOffset: 0, args: { modelHash: fill(32, 0), ciphertextCommitment: fill(32, 0), stateVersion: 1n << 64n, groth16: g16 } }),
    ).toThrow(/out of range/);
  });
});
