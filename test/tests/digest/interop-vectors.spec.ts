import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys } from "../../../src/derivation/fiber-scheme";
import { computeChannelAnnouncementDigest } from "../../../src/digest/channel-announcement";
import {
    buildCommitmentLockArgs,
    buildCommitmentTx,
    computeCommitmentTxDigest,
    readCommitmentLockDelay,
    readCommitmentLockLayout,
    readCommitmentLockVersion,
} from "../../../src/digest/commitment-tx";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import { calculateTxFee, commitmentTxSize, shutdownTxSize } from "../../../src/digest/fee";
import { buildRevocationContent, computeRevocationDigest } from "../../../src/digest/revocation";
import { settlementToCommitmentInput } from "../../../src/digest/settlement-input";
import { buildSettlementWitness } from "../../../src/digest/settlement-witness";
import { buildClosingTx, computeClosingTxDigest, computeShutdownTxDigest, readClosingTx } from "../../../src/digest/shutdown-tx";
import { computeRevocationContentMessage, computeTxMessage } from "../../../src/digest/tx-message";
import { moleculeCellOutput } from "../../../src/digest/utils/molecule.utils";
import { aggregateXOnlyPubkey } from "../../../src/digest/utils/digest.utils";
import {
    toChannelAnnouncementInput,
    toClosingTxInput,
    toCommitmentSettlementTerms,
    toCommitmentTxInput,
    toLockLayout,
    toOutPoint,
    toRevocationInput,
    toRevocationOutput,
    toScript,
    toScriptOrNull,
    toShutdownTxInput,
    toTlc,
    toTransaction,
} from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors, toVectorSettlement } from "../../utils/interop-vectors";

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

    // Both layouts are pinned by case name, so a regeneration that drops either side cannot stay green.
    describe("lock layouts", () => {
        it.each([
            ["ckb, no tlcs, for remote", "legacy"],
            ["ckb, three tlcs channel, opening, for remote", "legacy"],
            ["ckb, three tlcs, for remote", "legacy"],
            ["ckb, three tlcs, for local", "legacy"],
            ["udt, two tlcs, for remote", "legacy"],
            ["ckb, no tlcs, for remote, full payment hash", "full_payment_hash"],
            ["ckb, three tlcs, for remote, full payment hash", "full_payment_hash"],
            ["ckb, three tlcs, for local, full payment hash", "full_payment_hash"],
            ["udt, two tlcs, for remote, full payment hash", "full_payment_hash"],
        ])("carry the commitment case %p under %s", (name, layout) => {
            expect(caseOf(digest.commitment_cases, name).lock_layout).toBe(layout);
        });

        it.each([
            ["ckb, send side", "legacy"],
            ["udt, receive side", "legacy"],
            ["ckb, send side, full payment hash", "full_payment_hash"],
        ])("carry the revocation case %p under %s", (name, layout) => {
            expect(caseOf(digest.revocation_cases, name).lock_layout).toBe(layout);
        });
    });

    describe("commitment tx", () => {
        for (const kase of digest.commitment_cases) {
            describe(kase.name, () => {
                const isUdt = kase.udt_type_script !== null;
                const lockLayout = toLockLayout(kase.lock_layout);
                const input = toCommitmentTxInput(kase, digest.remote);

                it("rebuilds the settlement witness", () => {
                    const witness = buildSettlementWitness(keys, {
                        forRemote: kase.for_remote,
                        remoteTlcBasePubkey,
                        localAmountShannons: BigInt(kase.settlement_local) + (isUdt ? 0n : BigInt(kase.local_reserved)),
                        remoteAmountShannons: BigInt(kase.settlement_remote) + (isUdt ? 0n : BigInt(kase.remote_reserved)),
                        tlcs: kase.tlcs.map(toTlc),
                        lockLayout,
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
                        lockLayout,
                    );
                    expect(bytesToHex(lockArgs)).toBe(kase.lock_args);
                });

                it("reads the layout, the delay and the version back from the lock args", () => {
                    const lockArgs = hexToBytes(kase.lock_args);
                    expect(readCommitmentLockLayout(lockArgs)).toBe(lockLayout);
                    expect(readCommitmentLockDelay(lockArgs)).toBe(BigInt(kase.delay_epoch));
                    expect(readCommitmentLockVersion(lockArgs)).toBe(kase.commitment_number);
                });

                it("sizes the mock tx and its fee", () => {
                    const txSize = commitmentTxSize(
                        kase.cell_deps_count,
                        toScriptOrNull(kase.udt_type_script),
                        COMMITMENT_LOCK_TESTNET,
                        lockLayout,
                    );
                    expect(txSize).toBe(kase.tx_size);
                    expect(calculateTxFee(BigInt(kase.fee_rate), txSize)).toBe(BigInt(kase.fee));
                });

                it("recomputes the digest", () => {
                    expect(bytesToHex(computeCommitmentTxDigest(keys, input))).toBe(kase.digest);
                });

                it("hashes the tx fiber built to the same message", () => {
                    const tx = toTransaction(kase.transaction);
                    expect(bytesToHex(computeTxMessage(tx))).toBe(kase.digest);
                    expect(bytesToHex(tx.outputs[0]?.lock.args ?? new Uint8Array(0))).toBe(kase.lock_args);
                });

                it("builds the tx fiber built, whose message is the digest", () => {
                    const built = buildCommitmentTx(keys, input);
                    expect(built).toEqual(toTransaction(kase.transaction));
                    expect(bytesToHex(computeTxMessage(built))).toBe(kase.digest);
                });

                it("recomputes the digest from the settlement snapshot fiber states for it", () => {
                    const converted = settlementToCommitmentInput(
                        keys,
                        toVectorSettlement(kase.settlement),
                        toCommitmentSettlementTerms(kase, digest.remote),
                        kase.commitment_number,
                    );
                    // fiber lists the TLCs in its witness order, not the case's: the builder sorts them either way.
                    expect(converted).toEqual({ ...input, tlcs: expect.arrayContaining(input.tlcs) });
                    expect(converted.tlcs).toHaveLength(input.tlcs.length);
                    expect(bytesToHex(computeCommitmentTxDigest(keys, converted))).toBe(kase.digest);
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
                    expect(calculateTxFee(BigInt(kase.local_fee_rate), txSize)).toBe(BigInt(kase.local_fee));
                    expect(calculateTxFee(BigInt(kase.remote_fee_rate), txSize)).toBe(BigInt(kase.remote_fee));
                });

                it("recomputes the digest", () => {
                    const recomputed = computeShutdownTxDigest(keys, toShutdownTxInput(kase, digest.remote));
                    expect(bytesToHex(recomputed)).toBe(kase.digest);
                });

                it("hashes the tx fiber built to the same message", () => {
                    expect(bytesToHex(computeTxMessage(toTransaction(kase.transaction)))).toBe(kase.digest);
                });

                if (kase.udt_type_script === null) {
                    it("builds the tx fiber built from what it states, whose message is the digest", () => {
                        const built = buildClosingTx(keys, toClosingTxInput(kase, digest.remote), null);
                        expect(built).toEqual(toTransaction(kase.transaction));
                        expect(bytesToHex(computeTxMessage(built))).toBe(kase.digest);
                    });

                    it("recomputes the digest from what the closing tx states, from both sides of the channel", () => {
                        const closing = toClosingTxInput(kase, digest.remote);
                        expect(bytesToHex(computeClosingTxDigest(keys, closing))).toBe(kase.digest);
                        const fromPeer = computeClosingTxDigest(remoteKeys, {
                            fundingOutPoint: closing.fundingOutPoint,
                            remoteFundingPubkey: localFundingPubkey,
                            localCloseScript: closing.remoteCloseScript,
                            remoteCloseScript: closing.localCloseScript,
                            localCapacityShannons: closing.remoteCapacityShannons,
                            remoteCapacityShannons: closing.localCapacityShannons,
                        });
                        expect(bytesToHex(fromPeer)).toBe(kase.digest);
                    });

                    it("reads the closing input out of the tx fiber built, from both sides of the channel", () => {
                        const closing = toClosingTxInput(kase, digest.remote);
                        const tx = toTransaction(kase.transaction);
                        expect(readClosingTx(keys, remoteFundingPubkey, tx)).toEqual(closing);
                        expect(readClosingTx(remoteKeys, localFundingPubkey, tx)).toEqual({
                            fundingOutPoint: closing.fundingOutPoint,
                            remoteFundingPubkey: localFundingPubkey,
                            localCloseScript: closing.remoteCloseScript,
                            remoteCloseScript: closing.localCloseScript,
                            localCapacityShannons: closing.remoteCapacityShannons,
                            remoteCapacityShannons: closing.localCapacityShannons,
                        });
                    });
                }

                // The peer's view: every input swaps sides, the tx stays, and the output sort takes its other branch.
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
            describe(kase.name, () => {
                it("recomputes the digest", () => {
                    const recomputed = computeRevocationDigest(keys, toRevocationInput(kase, digest.remote));
                    expect(bytesToHex(recomputed)).toBe(kase.digest);
                });

                it("hashes the content fiber built to the same message", () => {
                    const output = toRevocationOutput(kase);
                    expect(bytesToHex(moleculeCellOutput(output.capacityShannons, output.lock, output.type))).toBe(kase.output);
                    const message = computeRevocationContentMessage(
                        output,
                        hexToBytes(kase.output_data),
                        hexToBytes(kase.commitment_lock_script_args),
                    );
                    expect(bytesToHex(message)).toBe(kase.digest);
                });

                it("builds the content fiber built, whose message is the digest", () => {
                    const { output, outputData, commitmentLockArgs } = buildRevocationContent(keys, toRevocationInput(kase, digest.remote));
                    expect(bytesToHex(moleculeCellOutput(output.capacityShannons, output.lock, output.type))).toBe(kase.output);
                    expect(bytesToHex(outputData)).toBe(kase.output_data);
                    expect(bytesToHex(commitmentLockArgs)).toBe(kase.commitment_lock_script_args);
                    expect(bytesToHex(computeRevocationContentMessage(output, outputData, commitmentLockArgs))).toBe(kase.digest);
                });

                it("reads the revoked number and the delay back from the content's args", () => {
                    const args = hexToBytes(kase.commitment_lock_script_args);
                    expect(readCommitmentLockVersion(args)).toBe(kase.revoked_commitment_number);
                    expect(readCommitmentLockDelay(args)).toBe(BigInt(kase.delay_epoch));
                });
            });
        }
    });

    describe("channel announcement", () => {
        for (const kase of digest.announcement_cases) {
            it(`recomputes the "${kase.name}" digest`, () => {
                const recomputed = computeChannelAnnouncementDigest(keys, toChannelAnnouncementInput(kase, digest.remote));
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
