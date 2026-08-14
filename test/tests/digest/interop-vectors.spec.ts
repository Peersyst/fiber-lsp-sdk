import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys } from "../../../src/derivation/fiber-scheme";
import { computeChannelAnnouncementDigest } from "../../../src/digest/channel-announcement";
import { buildCommitmentLockArgs, computeCommitmentTxDigest } from "../../../src/digest/commitment-tx";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import { calculateFee, commitmentTxSize, shutdownTxSize } from "../../../src/digest/fee";
import { computeRevocationDigest } from "../../../src/digest/revocation";
import { buildSettlementWitness } from "../../../src/digest/settlement-witness";
import { computeShutdownTxDigest } from "../../../src/digest/shutdown-tx";
import { aggregateXOnlyPubkey } from "../../../src/digest/utils/digest.utils";
import { toOutPoint, toScript, toScriptOrNull, toTlc } from "../../utils/digest-inputs";
import { loadInteropVectors } from "../../utils/interop-vectors";

const vectors = loadInteropVectors();
const digest = vectors.digest;

const keys = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const localFundingPubkey = hexToBytes(vectors.sdk_scheme.channel.channel_keys.funding_pubkey);
const remoteFundingPubkey = hexToBytes(digest.remote.funding_pubkey);
const remoteTlcBasePubkey = hexToBytes(digest.remote.tlc_base_pubkey);

// The peer's side of each fixture channel, re-derived from its seed: what the counterparty device would compute.
const remoteKeys = deriveChannelKeys(hexToBytes(digest.remote.seed));

describe("digest cross-implementation vectors", () => {
    it("uses the SDK's testnet commitment lock preset", () => {
        expect(bytesToHex(COMMITMENT_LOCK_TESTNET.codeHash)).toBe(digest.commitment_lock.code_hash);
        expect(COMMITMENT_LOCK_TESTNET.hashType).toBe(digest.commitment_lock.hash_type);
    });

    describe("commitment tx", () => {
        for (const kase of digest.commitment_cases) {
            describe(kase.name, () => {
                const isUdt = kase.udt_type_script !== null;
                const input = {
                    forRemote: kase.for_remote,
                    fundingOutPoint: toOutPoint(kase.funding_out_point),
                    remoteFundingPubkey,
                    remoteTlcBasePubkey,
                    commitmentNumber: kase.commitment_number,
                    commitmentDelayEpoch: BigInt(kase.delay_epoch),
                    commitmentFeeRate: BigInt(kase.fee_rate),
                    cellDepsCount: kase.cell_deps_count,
                    udtTypeScript: toScriptOrNull(kase.udt_type_script),
                    toLocalShannons: BigInt(kase.to_local),
                    toRemoteShannons: BigInt(kase.to_remote),
                    settlementLocalShannons: BigInt(kase.settlement_local),
                    settlementRemoteShannons: BigInt(kase.settlement_remote),
                    localReservedCkbShannons: BigInt(kase.local_reserved),
                    remoteReservedCkbShannons: BigInt(kase.remote_reserved),
                    tlcs: kase.tlcs.map(toTlc),
                    commitmentLock: COMMITMENT_LOCK_TESTNET,
                };

                it("rebuilds the settlement witness", () => {
                    const witness = buildSettlementWitness(keys, {
                        forRemote: kase.for_remote,
                        remoteTlcBasePubkey,
                        localAmountShannons: BigInt(kase.settlement_local) + (isUdt ? 0n : BigInt(kase.local_reserved)),
                        remoteAmountShannons: BigInt(kase.settlement_remote) + (isUdt ? 0n : BigInt(kase.remote_reserved)),
                        tlcs: kase.tlcs.map(toTlc),
                    });
                    expect(bytesToHex(witness)).toBe(kase.settlement_witness);
                });

                it("rebuilds the lock args", () => {
                    const orderedPubkeys: [Uint8Array, Uint8Array] = kase.for_remote
                        ? [localFundingPubkey, remoteFundingPubkey]
                        : [remoteFundingPubkey, localFundingPubkey];
                    const lockArgs = buildCommitmentLockArgs(
                        aggregateXOnlyPubkey(orderedPubkeys),
                        BigInt(kase.delay_epoch),
                        kase.commitment_number,
                        hexToBytes(kase.settlement_witness),
                    );
                    expect(bytesToHex(lockArgs)).toBe(kase.lock_args);
                });

                it("sizes the mock tx and its fee", () => {
                    const txSize = commitmentTxSize(kase.cell_deps_count, toScriptOrNull(kase.udt_type_script), COMMITMENT_LOCK_TESTNET);
                    expect(txSize).toBe(kase.tx_size);
                    expect(calculateFee(BigInt(kase.fee_rate), txSize)).toBe(BigInt(kase.fee));
                });

                it("recomputes the digest", () => {
                    expect(bytesToHex(computeCommitmentTxDigest(keys, input))).toBe(kase.digest);
                });
            });
        }
    });

    describe("shutdown tx", () => {
        for (const kase of digest.shutdown_cases) {
            describe(kase.name, () => {
                it("sizes the mock tx and both fees", () => {
                    const txSize = shutdownTxSize(kase.cell_deps_count, toScriptOrNull(kase.udt_type_script), [
                        toScript(kase.local_close_script),
                        toScript(kase.remote_close_script),
                    ]);
                    expect(txSize).toBe(kase.tx_size);
                    expect(calculateFee(BigInt(kase.local_fee_rate), txSize)).toBe(BigInt(kase.local_fee));
                    expect(calculateFee(BigInt(kase.remote_fee_rate), txSize)).toBe(BigInt(kase.remote_fee));
                });

                it("recomputes the digest", () => {
                    const recomputed = computeShutdownTxDigest(keys, {
                        fundingOutPoint: toOutPoint(kase.funding_out_point),
                        remoteFundingPubkey,
                        localCloseScript: toScript(kase.local_close_script),
                        remoteCloseScript: toScript(kase.remote_close_script),
                        localFeeRate: BigInt(kase.local_fee_rate),
                        remoteFeeRate: BigInt(kase.remote_fee_rate),
                        cellDepsCount: kase.cell_deps_count,
                        udtTypeScript: toScriptOrNull(kase.udt_type_script),
                        toLocalShannons: BigInt(kase.to_local),
                        toRemoteShannons: BigInt(kase.to_remote),
                        localReservedCkbShannons: BigInt(kase.local_reserved),
                        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
                    });
                    expect(bytesToHex(recomputed)).toBe(kase.digest);
                });

                // Same channel seen from the peer: every local/remote input swaps, the wire tx is identical, and the
                // opposite branch of the funding-pubkey output sort gets exercised against the same Rust digest.
                it("recomputes the same digest from the other side of the channel", () => {
                    const recomputed = computeShutdownTxDigest(remoteKeys, {
                        fundingOutPoint: toOutPoint(kase.funding_out_point),
                        remoteFundingPubkey: localFundingPubkey,
                        localCloseScript: toScript(kase.remote_close_script),
                        remoteCloseScript: toScript(kase.local_close_script),
                        localFeeRate: BigInt(kase.remote_fee_rate),
                        remoteFeeRate: BigInt(kase.local_fee_rate),
                        cellDepsCount: kase.cell_deps_count,
                        udtTypeScript: toScriptOrNull(kase.udt_type_script),
                        toLocalShannons: BigInt(kase.to_remote),
                        toRemoteShannons: BigInt(kase.to_local),
                        localReservedCkbShannons: BigInt(kase.remote_reserved),
                        remoteReservedCkbShannons: BigInt(kase.local_reserved),
                    });
                    expect(bytesToHex(recomputed)).toBe(kase.digest);
                });
            });
        }
    });

    describe("revocation", () => {
        for (const kase of digest.revocation_cases) {
            it(`recomputes the "${kase.name}" digest`, () => {
                const recomputed = computeRevocationDigest(keys, {
                    forRemote: kase.for_remote,
                    revokedCommitmentNumber: kase.revoked_commitment_number,
                    payoutScript: toScript(kase.payout_script),
                    remoteFundingPubkey,
                    commitmentDelayEpoch: BigInt(kase.delay_epoch),
                    commitmentFeeRate: BigInt(kase.fee_rate),
                    cellDepsCount: kase.cell_deps_count,
                    udtTypeScript: toScriptOrNull(kase.udt_type_script),
                    toLocalShannons: BigInt(kase.to_local),
                    toRemoteShannons: BigInt(kase.to_remote),
                    localReservedCkbShannons: BigInt(kase.local_reserved),
                    remoteReservedCkbShannons: BigInt(kase.remote_reserved),
                    commitmentLock: COMMITMENT_LOCK_TESTNET,
                });
                expect(bytesToHex(recomputed)).toBe(kase.digest);
            });
        }
    });

    describe("channel announcement", () => {
        for (const kase of digest.announcement_cases) {
            it(`recomputes the "${kase.name}" digest`, () => {
                const recomputed = computeChannelAnnouncementDigest(keys, {
                    chainHash: hexToBytes(kase.chain_hash),
                    fundingOutPoint: toOutPoint(kase.funding_out_point),
                    nodeIds: [hexToBytes(kase.node_ids[0]), hexToBytes(kase.node_ids[1])],
                    remoteFundingPubkey,
                    capacityShannons: BigInt(kase.capacity),
                    udtTypeScript: toScriptOrNull(kase.udt_type_script),
                });
                expect(bytesToHex(recomputed)).toBe(kase.digest);
            });

            it(`recomputes the "${kase.name}" digest from the other side of the channel`, () => {
                const recomputed = computeChannelAnnouncementDigest(remoteKeys, {
                    chainHash: hexToBytes(kase.chain_hash),
                    fundingOutPoint: toOutPoint(kase.funding_out_point),
                    nodeIds: [hexToBytes(kase.node_ids[0]), hexToBytes(kase.node_ids[1])],
                    remoteFundingPubkey: localFundingPubkey,
                    capacityShannons: BigInt(kase.capacity),
                    udtTypeScript: toScriptOrNull(kase.udt_type_script),
                });
                expect(bytesToHex(recomputed)).toBe(kase.digest);
            });
        }
    });
});
