import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import type { Script } from "../common";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertAnyBytes,
    assertBytes,
    assertOneOf,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
    ckbBlake2b,
    uint128Le,
    uint64Le,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, pubkeyOf } from "../derivation";
import {
    COMMITMENT_LOCK_ARGS_LENGTHS,
    COMMITMENT_LOCK_LAYOUTS,
    FULL_PAYMENT_HASH_FEATURE_BYTE,
    MAX_CAPACITY_SHANNONS,
    MAX_SINCE_PAYLOAD,
    SINCE_RELATIVE_EPOCH_FLAGS,
} from "./digest.constants";
import type { CommitmentLockLayout, CommitmentTxInput } from "./digest.types";
import { calculateCommitmentTxFee } from "./fee";
import { buildSettlementWitness } from "./settlement-witness";
import { aggregateXOnlyPubkey, moleculeCellInput, moleculeCellOutput, moleculeRawTransaction, subtractTxFee, uint64Be } from "./utils";

/**
 * Builds the commitment lock args: key hash, delay, version, settlement hash, trailing zero, and the feature byte under `fullPaymentHash`.
 * @param xonlyAggregatedPubkey The 32-byte x-only aggregate of the funding pubkeys in role order.
 * @param commitmentDelayEpoch The negotiated delay as an `EpochNumberWithFraction` full value.
 * @param commitmentNumber The commitment number this lock versions.
 * @param settlementWitness The settlement witness the args commit to.
 * @param lockLayout The layout the args are written under.
 * @returns The 57 bytes under `legacy`, 58 under `fullPaymentHash`.
 */
export function buildCommitmentLockArgs(
    xonlyAggregatedPubkey: Uint8Array,
    commitmentDelayEpoch: bigint,
    commitmentNumber: number,
    settlementWitness: Uint8Array,
    lockLayout: CommitmentLockLayout,
): Uint8Array {
    assertUnsignedBigInt("commitmentDelayEpoch", commitmentDelayEpoch, MAX_SINCE_PAYLOAD);
    assertUnsignedInteger("commitmentNumber", commitmentNumber, MAX_COMMITMENT_NUMBER);
    assertOneOf("lockLayout", lockLayout, COMMITMENT_LOCK_LAYOUTS);
    const featureBytes = lockLayout === "fullPaymentHash" ? Uint8Array.of(FULL_PAYMENT_HASH_FEATURE_BYTE) : new Uint8Array(0);
    return concatBytes(
        blake160(xonlyAggregatedPubkey),
        uint64Le(SINCE_RELATIVE_EPOCH_FLAGS | commitmentDelayEpoch),
        uint64Be(BigInt(commitmentNumber)),
        blake160(settlementWitness),
        Uint8Array.of(0x00),
        featureBytes,
    );
}

/**
 * Port of fiber's `CommitmentContractFeatures::from_lock_args`: the layout a commitment lock's args were written under.
 * @param args The commitment lock args as the node attached them.
 * @returns The layout.
 */
export function readCommitmentLockLayout(args: Uint8Array): CommitmentLockLayout {
    assertAnyBytes("commitment lock args", args);
    const { legacy, fullPaymentHash } = COMMITMENT_LOCK_ARGS_LENGTHS;
    if (args.length === legacy) return "legacy";
    if (args.length !== fullPaymentHash) {
        throw new TypeError(`commitment lock args must be ${legacy} or ${fullPaymentHash} bytes, got ${args.length}`);
    }
    // Fiber reads 58 bytes ending in 0x00 as legacy too, but never writes them.
    const featureBytes = args.subarray(legacy);
    if (featureBytes[0] !== FULL_PAYMENT_HASH_FEATURE_BYTE) {
        throw new TypeError(
            `commitment lock args of ${fullPaymentHash} bytes must end in the feature byte 0x01, got 0x${bytesToHex(featureBytes)}`,
        );
    }
    return "fullPaymentHash";
}

/**
 * Recomputes the digest of a commitment tx: what fiber's `compute_tx_message` produces over `build_commitment_tx_and_settlement_data`.
 * @param keys The channel's four secrets.
 * @param input Everything the tx is a function of, as the node attached it.
 * @returns The 32-byte digest a compliant signing request must carry.
 */
export function computeCommitmentTxDigest(keys: FiberChannelKeys, input: CommitmentTxInput): Uint8Array {
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("toLocalShannons", input.toLocalShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("toRemoteShannons", input.toRemoteShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("localReservedCkbShannons", input.localReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("remoteReservedCkbShannons", input.remoteReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("settlementLocalShannons", input.settlementLocalShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("settlementRemoteShannons", input.settlementRemoteShannons, MAX_AMOUNT_SHANNONS);

    const localFundingPubkey = pubkeyOf(keys.fundingKey);
    const orderedPubkeys: [Uint8Array, Uint8Array] = input.forRemote
        ? [localFundingPubkey, input.remoteFundingPubkey]
        : [input.remoteFundingPubkey, localFundingPubkey];
    const isUdt = input.udtTypeScript !== null;
    // On CKB channels the settlement amounts absorb each side's reserved CKB; on UDT channels the reserve stays capacity-only.
    const witness = buildSettlementWitness(keys, {
        forRemote: input.forRemote,
        remoteTlcBasePubkey: input.remoteTlcBasePubkey,
        localAmountShannons: isUdt ? input.settlementLocalShannons : input.settlementLocalShannons + input.localReservedCkbShannons,
        remoteAmountShannons: isUdt ? input.settlementRemoteShannons : input.settlementRemoteShannons + input.remoteReservedCkbShannons,
        tlcs: input.tlcs,
        lockLayout: input.lockLayout,
    });
    const lockArgs = buildCommitmentLockArgs(
        aggregateXOnlyPubkey(orderedPubkeys),
        input.commitmentDelayEpoch,
        input.commitmentNumber,
        witness,
        input.lockLayout,
    );
    const lock: Script = { ...input.commitmentLock, args: lockArgs };

    const fee = calculateCommitmentTxFee(input);
    const liquidCapacity = input.toLocalShannons + input.toRemoteShannons;
    assertUnsignedBigInt("liquid capacity", liquidCapacity, MAX_AMOUNT_SHANNONS);
    const totalReserved = input.localReservedCkbShannons + input.remoteReservedCkbShannons;
    const capacity = subtractTxFee(isUdt ? totalReserved : liquidCapacity + totalReserved, fee);
    const outputData = isUdt ? uint128Le(liquidCapacity) : new Uint8Array(0);

    const raw = moleculeRawTransaction({
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [moleculeCellInput(0n, input.fundingOutPoint)],
        outputs: [moleculeCellOutput(capacity, lock, input.udtTypeScript)],
        outputsData: [outputData],
    });
    return ckbBlake2b(raw);
}
