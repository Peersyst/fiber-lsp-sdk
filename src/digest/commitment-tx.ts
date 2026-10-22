import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import type { Script, Transaction } from "../common";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    UINT64_LENGTH,
    assertAnyBytes,
    assertBytes,
    assertOneOf,
    assertOutPoint,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
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
    REVOCATION_LOCK_ARGS_LENGTH,
    SINCE_RELATIVE_EPOCH_FLAGS,
} from "./digest.constants";
import type { CommitmentLockLayout, CommitmentTxInput } from "./digest.types";
import { calculateCommitmentTxFee } from "./fee";
import { buildSettlementWitness } from "./settlement-witness";
import { computeTxMessage } from "./tx-message";
import { aggregateXOnlyPubkey, commitmentCellValue, uint64Be } from "./utils";

// Both fields sit after the 20-byte key hash, at the same offsets in a commitment's args and in a revocation's.
const LOCK_ARGS_DELAY_OFFSET = 20;
const LOCK_ARGS_VERSION_OFFSET = LOCK_ARGS_DELAY_OFFSET + UINT64_LENGTH;

/**
 * Key hash, delay, version, settlement hash, trailing zero, and the feature byte under `fullPaymentHash`.
 * @param xonlyAggregatedPubkey The x-only aggregate of the funding pubkeys in role order.
 * @param commitmentDelayEpoch The full `EpochNumberWithFraction` value.
 * @param commitmentNumber The version.
 * @param settlementWitness The witness the args commit to.
 * @param lockLayout The layout.
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
 * Port of fiber's `CommitmentContractFeatures::from_lock_args`.
 * @param args The commitment lock args.
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
 * Reads the delay out of a commitment lock's args or a revoked cell's.
 * @param args The 36, 57 or 58 bytes.
 * @returns The full `EpochNumberWithFraction` value, flags stripped.
 */
export function readCommitmentLockDelay(args: Uint8Array): bigint {
    const since = readLockArgsField(args, LOCK_ARGS_DELAY_OFFSET, true);
    if ((since & ~MAX_SINCE_PAYLOAD) !== SINCE_RELATIVE_EPOCH_FLAGS) {
        throw new TypeError(`commitment lock args must carry a relative epoch delay, got the since 0x${since.toString(16)}`);
    }
    return since & MAX_SINCE_PAYLOAD;
}

/**
 * Reads the version out of a commitment lock's args or a revoked cell's.
 * @param args The 36, 57 or 58 bytes.
 * @returns The commitment number.
 */
export function readCommitmentLockVersion(args: Uint8Array): number {
    const version = readLockArgsField(args, LOCK_ARGS_VERSION_OFFSET, false);
    if (version > BigInt(MAX_COMMITMENT_NUMBER)) {
        throw new RangeError(`commitment lock args must carry a version of at most ${MAX_COMMITMENT_NUMBER}, got ${version}`);
    }
    return Number(version);
}

/**
 * Reads one u64 of the 36 bytes a commitment's args and a revocation's share, after checking the length.
 * @param args The args.
 * @param offset Where the u64 starts.
 * @param littleEndian The delay is little-endian, the version big-endian.
 * @returns The value.
 */
function readLockArgsField(args: Uint8Array, offset: number, littleEndian: boolean): bigint {
    assertAnyBytes("commitment lock args", args);
    const { legacy, fullPaymentHash } = COMMITMENT_LOCK_ARGS_LENGTHS;
    if (args.length !== REVOCATION_LOCK_ARGS_LENGTH && args.length !== legacy && args.length !== fullPaymentHash) {
        throw new TypeError(
            `commitment lock args must be ${REVOCATION_LOCK_ARGS_LENGTH}, ${legacy} or ${fullPaymentHash} bytes, got ${args.length}`,
        );
    }
    return new DataView(args.buffer, args.byteOffset, args.byteLength).getBigUint64(offset, littleEndian);
}

/**
 * Fiber's `compute_tx_message` over `build_commitment_tx_and_settlement_data`.
 * @param keys The channel's secrets.
 * @param input What the tx is a function of.
 * @returns The 32-byte digest.
 */
export function computeCommitmentTxDigest(keys: FiberChannelKeys, input: CommitmentTxInput): Uint8Array {
    return computeTxMessage(buildCommitmentTx(keys, input));
}

/**
 * The tx of fiber's `build_commitment_tx_and_settlement_data`.
 * @param keys The channel's secrets.
 * @param input What the tx is a function of.
 * @returns The unsigned tx, without cell deps.
 */
export function buildCommitmentTx(keys: FiberChannelKeys, input: CommitmentTxInput): Transaction {
    assertOutPoint("fundingOutPoint", input.fundingOutPoint);
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("liquidCapacityShannons", input.liquidCapacityShannons, MAX_AMOUNT_SHANNONS);
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

    const { capacityShannons, data } = commitmentCellValue(input, calculateCommitmentTxFee(input));
    return {
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [{ since: 0n, previousOutput: input.fundingOutPoint }],
        outputs: [{ capacityShannons, lock, type: input.udtTypeScript }],
        outputsData: [data],
        witnesses: [],
    };
}
