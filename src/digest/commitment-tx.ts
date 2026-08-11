import { concatBytes } from "@noble/hashes/utils.js";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertBytes,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
    ckbBlake2b,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS, MAX_SINCE_PAYLOAD, SINCE_RELATIVE_EPOCH_FLAGS } from "./digest.constants";
import type { CommitmentTxInput, Script } from "./digest.types";
import { calculateFee, commitmentTxSize } from "./fee";
import { buildSettlementWitness } from "./settlement-witness";
import {
    aggregateXOnlyPubkey,
    encodeCellInput,
    encodeCellOutput,
    encodeRawTransaction,
    subtractFee,
    uint128Le,
    uint64Be,
    uint64Le,
} from "./utils";

/**
 * Builds the 57-byte commitment lock args: key hash, delay, version, settlement hash, trailing zero.
 * @param xonlyAggregatedPubkey The 32-byte x-only aggregate of the funding pubkeys in role order.
 * @param commitmentDelayEpoch The negotiated delay as an `EpochNumberWithFraction` full value.
 * @param commitmentNumber The commitment number this lock versions.
 * @param settlementWitness The settlement witness the args commit to.
 * @returns The 57 bytes.
 */
export function buildCommitmentLockArgs(
    xonlyAggregatedPubkey: Uint8Array,
    commitmentDelayEpoch: bigint,
    commitmentNumber: number,
    settlementWitness: Uint8Array,
): Uint8Array {
    assertUnsignedBigInt("commitmentDelayEpoch", commitmentDelayEpoch, MAX_SINCE_PAYLOAD);
    assertUnsignedInteger("commitmentNumber", commitmentNumber, MAX_COMMITMENT_NUMBER);
    return concatBytes(
        blake160(xonlyAggregatedPubkey),
        uint64Le(SINCE_RELATIVE_EPOCH_FLAGS | commitmentDelayEpoch),
        uint64Be(BigInt(commitmentNumber)),
        blake160(settlementWitness),
        Uint8Array.of(0x00),
    );
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
    });
    const lockArgs = buildCommitmentLockArgs(
        aggregateXOnlyPubkey(orderedPubkeys),
        input.commitmentDelayEpoch,
        input.commitmentNumber,
        witness,
    );
    const lock: Script = { ...input.commitmentLock, args: lockArgs };

    const fee = calculateFee(input.commitmentFeeRate, commitmentTxSize(input.cellDepsCount, input.udtTypeScript, input.commitmentLock));
    const liquidCapacity = input.toLocalShannons + input.toRemoteShannons;
    assertUnsignedBigInt("liquid capacity", liquidCapacity, MAX_AMOUNT_SHANNONS);
    const totalReserved = input.localReservedCkbShannons + input.remoteReservedCkbShannons;
    const capacity = subtractFee(isUdt ? totalReserved : liquidCapacity + totalReserved, fee);
    const outputData = isUdt ? uint128Le(liquidCapacity) : new Uint8Array(0);

    const raw = encodeRawTransaction({
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [encodeCellInput(0n, input.fundingOutPoint)],
        outputs: [encodeCellOutput(capacity, lock, input.udtTypeScript)],
        outputsData: [outputData],
    });
    return ckbBlake2b(raw);
}
