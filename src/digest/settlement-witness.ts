import { concatBytes } from "@noble/hashes/utils.js";
import type { TlcDirection } from "../common";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    MILLISECONDS_PER_SECOND,
    PAYMENT_HASH_LENGTH,
    TLC_HASH_ALGORITHMS,
    TLC_HASH_ALGORITHM_BYTES,
    assertBytes,
    assertCompressedPoint,
    assertOneOf,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
    uint128Le,
    uint64Le,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, deriveTlcKey, pubkeyOf } from "../derivation";
import {
    COMMITMENT_LOCK_LAYOUTS,
    MAX_SETTLEMENT_TLCS,
    MAX_SINCE_PAYLOAD,
    SINCE_ABSOLUTE_TIMESTAMP_FLAG,
    WITNESS_PAYMENT_HASH_LENGTHS,
} from "./digest.constants";
import type { CommitmentLockLayout, SettlementTlc } from "./digest.types";

export type SettlementWitnessInput = {
    /**
     * Swaps every local/remote pair and flips the per-TLC direction flags.
     */
    forRemote: boolean;
    /**
     * Only the side block hashes it; TLC records hash the per-TLC key the node derived from it.
     */
    remoteTlcBasePubkey: Uint8Array;
    /**
     * Final: the caller adds each side's reserved CKB on non-UDT channels.
     */
    localAmountShannons: bigint;
    remoteAmountShannons: bigint;
    tlcs: SettlementTlc[];
    lockLayout: CommitmentLockLayout;
};

/**
 * Port of fiber's `settlement_data_to_witness`, whose blake160 the commitment lock args commit to.
 * @param keys The channel's secrets.
 * @param input The witness inputs.
 * @returns The `73 + n * (65 + h)` bytes, `h` 20 under `legacy` and 32 under `fullPaymentHash`.
 */
export function buildSettlementWitness(keys: FiberChannelKeys, input: SettlementWitnessInput): Uint8Array {
    const { forRemote, remoteTlcBasePubkey, localAmountShannons, remoteAmountShannons, tlcs, lockLayout } = input;
    assertBytes("remoteTlcBasePubkey", remoteTlcBasePubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("localAmountShannons", localAmountShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("remoteAmountShannons", remoteAmountShannons, MAX_AMOUNT_SHANNONS);
    if (!Array.isArray(tlcs) || tlcs.length > MAX_SETTLEMENT_TLCS) {
        throw new TypeError(`tlcs must be an array of at most ${MAX_SETTLEMENT_TLCS} TLCs`);
    }
    assertOneOf("lockLayout", lockLayout, COMMITMENT_LOCK_LAYOUTS);

    const records = orderTlcs(tlcs, forRemote).map((tlc) => buildTlcRecord(keys, tlc, forRemote, lockLayout));
    const localHash = blake160(pubkeyOf(keys.tlcBaseKey));
    const remoteHash = blake160(remoteTlcBasePubkey);
    const localBlock = concatBytes(localHash, uint128Le(localAmountShannons));
    const remoteBlock = concatBytes(remoteHash, uint128Le(remoteAmountShannons));
    const blocks = forRemote ? [remoteBlock, localBlock] : [localBlock, remoteBlock];
    return concatBytes(Uint8Array.of(records.length), ...records, ...blocks);
}

/**
 * Orders the TLCs as fiber's `get_active_tlcs`: two direction groups, each ascending by id.
 * @param tlcs The TLCs.
 * @param forRemote Decides which group goes first.
 * @returns The ordered TLCs.
 */
function orderTlcs(tlcs: SettlementTlc[], forRemote: boolean): SettlementTlc[] {
    const firstGroup: TlcDirection = forRemote ? "received" : "offered";
    /**
     * Compares two TLCs by id.
     * @param a A TLC.
     * @param b Another.
     * @returns Negative when `a` sorts first.
     */
    const byId = (a: SettlementTlc, b: SettlementTlc): number => a.id - b.id;
    const first = tlcs.filter((tlc) => tlc.direction === firstGroup).sort(byId);
    const second = tlcs.filter((tlc) => tlc.direction !== firstGroup).sort(byId);
    return [...first, ...second];
}

/**
 * Port of fiber's `settlement_tlc_to_witness`.
 * @param keys The channel's secrets.
 * @param tlc The TLC.
 * @param forRemote Flips the direction flag and swaps the key hashes.
 * @param lockLayout Sizes the payment hash the record binds.
 * @returns The 85 bytes under `legacy`, 97 under `fullPaymentHash`.
 */
function buildTlcRecord(keys: FiberChannelKeys, tlc: SettlementTlc, forRemote: boolean, lockLayout: CommitmentLockLayout): Uint8Array {
    assertUnsignedInteger("tlc.id", tlc.id, Number.MAX_SAFE_INTEGER);
    assertUnsignedBigInt("tlc.amountShannons", tlc.amountShannons, MAX_AMOUNT_SHANNONS);
    assertBytes("tlc.paymentHash", tlc.paymentHash, PAYMENT_HASH_LENGTH);
    assertUnsignedBigInt("tlc.expiryMs", tlc.expiryMs, MAX_SINCE_PAYLOAD * MILLISECONDS_PER_SECOND);
    assertUnsignedInteger("tlc.localKeyCommitmentNumber", tlc.localKeyCommitmentNumber, MAX_COMMITMENT_NUMBER);
    assertCompressedPoint("tlc.remoteTlcPubkey", tlc.remoteTlcPubkey);
    if (tlc.direction !== "offered" && tlc.direction !== "received") {
        throw new TypeError("tlc.direction must be offered or received");
    }
    assertOneOf("tlc.hashAlgorithm", tlc.hashAlgorithm, TLC_HASH_ALGORITHMS);

    // A for_remote=false witness flips every TLC id (fiber's flip_mut), which only shows up here, in the flag bit.
    const offeredBit = (tlc.direction === "offered") === forRemote ? 0 : 1;
    const flag = (TLC_HASH_ALGORITHM_BYTES[tlc.hashAlgorithm] << 1) | offeredBit;
    // Fiber's get_tlc_keys: the device's key derives at the local key number, the peer's arrives derived.
    const localHash = blake160(pubkeyOf(deriveTlcKey(keys, tlc.localKeyCommitmentNumber)));
    const remoteHash = blake160(tlc.remoteTlcPubkey);
    const keyHashes = forRemote ? [remoteHash, localHash] : [localHash, remoteHash];
    const since = SINCE_ABSOLUTE_TIMESTAMP_FLAG | (tlc.expiryMs / MILLISECONDS_PER_SECOND);
    return concatBytes(
        Uint8Array.of(flag),
        uint128Le(tlc.amountShannons),
        tlc.paymentHash.slice(0, WITNESS_PAYMENT_HASH_LENGTHS[lockLayout]),
        ...keyHashes,
        uint64Le(since),
    );
}
