import { describe, expect, it } from "vitest";
import { PublicKey } from "@solana/web3.js";
import { computeNullifier, computeNullifierBatch, NULLIFIER_PREFIX, nullifierPreimage } from "../src/nullifier.js";
import {
  BN254_R_BE,
  buildPublishPublicInputs,
  isCanonicalScalar,
  packPublicInputs,
  serializeProof,
  split128,
  verifyGroth16Offchain,
  PUBLISH_NR_INPUTS,
} from "../src/proof.js";
import { ClawdZkClient } from "../src/client.js";
import { discriminator } from "../src/encoding.js";
import type { Groth16Proof } from "../src/types.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

describe("nullifier v1", () => {
  it("is deterministic and 32 bytes", async () => {
    const a = await computeNullifier({ secret: fill(32, 0xab), context: "ctx" });
    expect(a).toEqual(await computeNullifier({ secret: fill(32, 0xab), context: "ctx" }));
    expect(a.length).toBe(32);
  });

  it("no longer collides when bytes shift between secret and context", () => {
    // Under the old sha256(secret‖context‖nonce) these two were identical.
    const s1 = Uint8Array.from([...fill(16, 1), 2]);
    const s2 = fill(16, 1);
    expect(hex(nullifierPreimage(s1, Uint8Array.from([3]), 0))).not.toBe(
      hex(nullifierPreimage(s2, Uint8Array.from([2, 3]), 0)),
    );
  });

  it("no longer aliases batch nonces with numeric nonces", async () => {
    const [n0, n1] = await computeNullifierBatch({ secret: fill(16, 9), context: "ctx" }, 2);
    expect(n1).toEqual(await computeNullifier({ secret: fill(16, 9), context: "ctx", nonce: 1 }));
    expect(n0).not.toEqual(n1);
  });

  it("rejects short secrets and out-of-range nonces", async () => {
    await expect(computeNullifier({ secret: fill(8, 0), context: "x" })).rejects.toThrow(/at least 16 bytes/);
    expect(() => nullifierPreimage(fill(16, 0), "x", 1n << 64n)).toThrow(/u64/);
    expect(() => nullifierPreimage(fill(16, 0), "x", -1)).toThrow(/u64/);
  });

  it("keeps the on-chain address seed prefix", () => {
    expect(Buffer.from(NULLIFIER_PREFIX).toString("utf8")).toBe("clawd-zk-nullifier");
  });
});

describe("BN254 public inputs", () => {
  it("split128 is canonical and lossless", () => {
    const x = fill(32, 0xff);
    expect(isCanonicalScalar(x)).toBe(false);
    const [hi, lo] = split128(x);
    expect(isCanonicalScalar(hi) && isCanonicalScalar(lo)).toBe(true);
    expect(hex(Uint8Array.from([...hi.subarray(16), ...lo.subarray(16)]))).toBe(hex(x));
  });

  it("r itself is not canonical; r-1 is", () => {
    expect(isCanonicalScalar(BN254_R_BE)).toBe(false);
    const rm1 = Uint8Array.from(BN254_R_BE);
    rm1[31] -= 1;
    expect(isCanonicalScalar(rm1)).toBe(true);
  });

  it("publish inputs: 8 canonical scalars", () => {
    const inputs = buildPublishPublicInputs({ attester: fill(32, 0xff), modelHash: fill(32, 0xff), payloadCommitment: fill(32, 0xff), nullifier: fill(32, 0xff) });
    expect(inputs.length).toBe(PUBLISH_NR_INPUTS);
    expect(inputs.every(isCanonicalScalar)).toBe(true);
    expect(packPublicInputs(inputs).length).toBe(8 * 32);
  });
});

describe("proof shape", () => {
  const proof: Groth16Proof = { a: fill(64, 1), b: fill(128, 2), c: fill(64, 3) };

  it("has no verifying key field and validates sizes", () => {
    expect(Object.keys(serializeProof(proof))).toEqual(["a", "b", "c"]);
    expect(() => serializeProof({ ...proof, a: fill(32, 0) })).toThrow(/proof\.a/);
  });

  it("off-chain check rejects non-canonical inputs and wrong counts", () => {
    expect(verifyGroth16Offchain({ proof, publicInputs: [fill(32, 0xff)] }).ok).toBe(false);
    expect(verifyGroth16Offchain({ proof, publicInputs: [fill(32, 1)], expectedInputs: 8 }).ok).toBe(false);
    expect(verifyGroth16Offchain({ proof, publicInputs: [fill(32, 0)], expectedInputs: 1 }).ok).toBe(true);
  });
});

describe("ClawdZkClient.consumeAttestation", () => {
  const client = new ClawdZkClient({ rpc: {}, programId: new PublicKey("4vJ9JU1bJJE96FWSVKmnrL3xFU5jSBSVdk9x4La2vzhn") });
  const base = {
    signer: new PublicKey(fill(32, 9)),
    record: {
      modelHash: fill(32, 1), attester: fill(32, 2), payloadCommitment: fill(32, 3), nullifier: fill(32, 4),
      allowedConsumer: fill(32, 0), publishedAt: 0n, status: 0, consumedBy: fill(32, 0), consumeNonce: fill(32, 0),
    },
    accountMeta: { treeInfo: { rootIndex: 0, proveByIndex: false, merkleTreePubkeyIndex: 0, queuePubkeyIndex: 1, leafIndex: 0 }, address: fill(32, 5), outputStateTreeIndex: 0 },
    validityProof: null,
    remainingAccounts: [],
    systemAccountsOffset: 0,
    consumeNonce: fill(32, 7),
    proof: { a: fill(64, 1), b: fill(128, 2), c: fill(64, 3) },
  };

  it("builds Borsh data with the Anchor discriminator and the signer first", () => {
    const ix = client.consumeAttestation(base);
    expect(hex(ix.data.subarray(0, 8))).toBe(hex(discriminator("consume_attestation")));
    expect(ix.keys[0].pubkey.equals(base.signer)).toBe(true);
    expect(ix.keys[0].isSigner).toBe(true);
  });

  it("refuses a zero nonce or an already-consumed record", () => {
    expect(() => client.consumeAttestation({ ...base, consumeNonce: fill(32, 0) })).toThrow(/non-zero/);
    expect(() => client.consumeAttestation({ ...base, record: { ...base.record, status: 1 } })).toThrow(/not active/);
  });
});
