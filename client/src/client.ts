/**
 * ClawdZkClient — builds ready-to-sign `clawd-zk` instructions.
 *
 * Instruction data is Borsh (see `encoding.ts`), not JSON. The Groth16
 * verifying key is pinned in the program and is never sent.
 *
 * NOTE: the Photon/Light RPC wiring (`state.ts`) is not yet exercised
 * against a Light test validator; the byte encodings are (golden vectors).
 */

import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import type { ClawdZkClientConfig, CommitStateArgs, PublishAttestationArgs, Groth16Proof } from "./types.js";
import { serializeProof } from "./proof.js";
import { fetchAddressTreeV2, fetchRandomStateTreeV2, fetchValidityProofV2, packAccounts, type ValidityProof } from "./state.js";
import { deriveAttestationAddress, deriveNullifierAddress, STATE_PREFIX } from "./nullifier.js";
import {
  encodeCommitEncryptedState,
  encodeConsumeAttestation,
  encodePublishAttestation,
  type AttestationRecord,
  type CompressedAccountMetaArgs,
  type LightValidityProof,
} from "./encoding.js";

/** Default program ID — matches `declare_id!` in programs/clawd-zk. Not deployed yet. */
export const CLAWD_ZK_PROGRAM_ID = new PublicKey("4vJ9JU1bJJE96FWSVKmnrL3xFU5jSBSVdk9x4La2vzhn");

const ZERO32 = new Uint8Array(32);

export interface ConsumeAttestationArgs {
  signer: PublicKey;
  /** Current record, as returned by Photon for the attestation address. */
  record: AttestationRecord;
  /** Packed account meta for the record (tree info, address, output tree). */
  accountMeta: CompressedAccountMetaArgs;
  /** Light validity proof (inclusion of the current record). */
  validityProof: LightValidityProof;
  /** Packed remaining accounts (Light system accounts + trees). */
  remainingAccounts: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[];
  systemAccountsOffset: number;
  /** Non-zero 32-byte nonce bound into the consume proof. */
  consumeNonce: Uint8Array;
  proof: Groth16Proof;
}

export class ClawdZkClient {
  readonly rpc: any;
  readonly programId: PublicKey;
  readonly photonUrl: string;
  readonly apiKey?: string;
  readonly commitment: "processed" | "confirmed" | "finalized";

  constructor(config: ClawdZkClientConfig) {
    this.rpc = config.rpc;
    this.programId = config.programId ?? CLAWD_ZK_PROGRAM_ID;
    this.photonUrl = config.photonUrl ?? "";
    this.apiKey = config.apiKey;
    this.commitment = config.commitment ?? "confirmed";
  }

  /** `publish_attestation`: creates the nullifier and the record in one Light CPI. */
  async publishAttestation(args: PublishAttestationArgs): Promise<TransactionInstruction> {
    const groth16 = serializeProof(args.proof);
    const addressTree = await fetchAddressTreeV2(this.rpc);
    const { address: nullifierAddress } = await deriveNullifierAddress(this.programId, addressTree, args.nullifier);
    const { address: recordAddress } = await deriveAttestationAddress(this.programId, addressTree, args.nullifier);

    const validity = await fetchValidityProofV2({
      rpc: this.rpc,
      hashes: [],
      addressesWithTrees: [
        { address: nullifierAddress, tree: addressTree },
        { address: recordAddress, tree: addressTree },
      ],
    });
    const stateTree = await fetchRandomStateTreeV2(this.rpc);
    const { packed, addressMerkleTreeIndex, outputStateTreeIndex } = await packAccounts({
      rpc: this.rpc,
      programId: this.programId,
      treeInfo: { addressTree, stateTree: stateTree.tree, outputQueue: stateTree.queue },
      proof: validity,
    });
    const { remainingAccounts, systemStart } = packed.toAccountMetas();

    const data = encodePublishAttestation({
      proof: toLightProof(validity),
      addressTreeInfo: {
        addressMerkleTreePubkeyIndex: addressMerkleTreeIndex,
        addressQueuePubkeyIndex: addressMerkleTreeIndex,
        rootIndex: validity.rootIndices[0] ?? 0,
      },
      outputStateTreeIndex,
      systemAccountsOffset: systemStart,
      args: {
        modelHash: args.modelHash,
        payloadCommitment: args.payloadCommitment,
        nullifier: args.nullifier,
        allowedConsumer: args.allowedConsumer?.toBytes() ?? ZERO32,
        groth16,
      },
    });
    return this.ix(args.signer, remainingAccounts, data);
  }

  /**
   * `consume_attestation`: lower-level — the caller supplies the record and
   * its packed meta/validity proof from Photon (`getCompressedAccount` +
   * `getValidityProofV0` over the record hash).
   */
  consumeAttestation(args: ConsumeAttestationArgs): TransactionInstruction {
    if (args.consumeNonce.length !== 32 || args.consumeNonce.every((b) => b === 0)) {
      throw new Error("consumeNonce must be 32 non-zero bytes");
    }
    if (args.record.status !== 0) throw new Error("attestation is not active");
    const data = encodeConsumeAttestation({
      proof: args.validityProof,
      accountMeta: args.accountMeta,
      systemAccountsOffset: args.systemAccountsOffset,
      record: args.record,
      consumeNonce: args.consumeNonce,
      groth16: serializeProof(args.proof),
    });
    return this.ix(args.signer, args.remainingAccounts, data);
  }

  /** `commit_encrypted_state`: one record per (model, committer, version). */
  async commitEncryptedState(args: CommitStateArgs): Promise<TransactionInstruction> {
    const groth16 = serializeProof(args.proof);
    const addressTree = await fetchAddressTreeV2(this.rpc);
    const version = new Uint8Array(8);
    new DataView(version.buffer).setBigUint64(0, BigInt(args.stateVersion), true);
    const sdk: any = await import("@lightprotocol/stateless.js");
    const seed = sdk.deriveAddressSeedV2([STATE_PREFIX, args.modelHash, args.signer.toBytes(), version]);
    const address = sdk.deriveAddressV2(seed, addressTree, this.programId);

    const validity = await fetchValidityProofV2({
      rpc: this.rpc,
      hashes: [],
      addressesWithTrees: [{ address, tree: addressTree }],
    });
    const stateTree = await fetchRandomStateTreeV2(this.rpc);
    const { packed, addressMerkleTreeIndex, outputStateTreeIndex } = await packAccounts({
      rpc: this.rpc,
      programId: this.programId,
      treeInfo: { addressTree, stateTree: stateTree.tree, outputQueue: stateTree.queue },
      proof: validity,
    });
    const { remainingAccounts, systemStart } = packed.toAccountMetas();

    const data = encodeCommitEncryptedState({
      proof: toLightProof(validity),
      addressTreeInfo: {
        addressMerkleTreePubkeyIndex: addressMerkleTreeIndex,
        addressQueuePubkeyIndex: addressMerkleTreeIndex,
        rootIndex: validity.rootIndices[0] ?? 0,
      },
      outputStateTreeIndex,
      systemAccountsOffset: systemStart,
      args: {
        modelHash: args.modelHash,
        ciphertextCommitment: args.ciphertextCommitment,
        stateVersion: args.stateVersion,
        groth16,
      },
    });
    return this.ix(args.signer, remainingAccounts, data);
  }

  private ix(
    signer: PublicKey,
    remaining: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[],
    data: Uint8Array,
  ): TransactionInstruction {
    return new TransactionInstruction({
      programId: this.programId,
      keys: [{ pubkey: signer, isSigner: true, isWritable: true }, ...remaining],
      data: Buffer.from(data),
    });
  }
}

function toLightProof(v: ValidityProof): LightValidityProof {
  const p = v.compressedProof;
  return { a: Uint8Array.from(p.a), b: Uint8Array.from(p.b), c: Uint8Array.from(p.c) };
}
