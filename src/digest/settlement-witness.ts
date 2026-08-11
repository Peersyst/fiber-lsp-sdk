import { concatBytes } from "@noble/hashes/utils.js";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    PAYMENT_HASH_LENGTH,
    assertBytes,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, derivePublicKey, deriveTlcKey, pubkeyOf } from "../derivation";
import { MAX_SETTLEMENT_TLCS, MAX_SINCE_PAYLOAD, SINCE_ABSOLUTE_TIMESTAMP_FLAG } from "./digest.constants";
import type { SettlementTlc, TlcDirection, TlcHashAlgorithm } from "./digest.types";
import { uint128Le, uint64Le } from "./utils";

const HASH_ALGORITHM_BITS: Record<TlcHashAlgorithm, number> = { "ckb-hash": 0, sha256: 1 };

const TRUNCATED_PAYMENT_HASH_LENGTH = 20;

const MILLISECONDS_PER_SECOND = 1000n;

export type SettlementWitnessInput = {
    /**
     * Fiber's direction parameter; it swaps every local/remote pair and flips the per-TLC direction flags.
     */
    forRemote: boolean;
    remoteTlcBasePubkey: Uint8Array;
    /**
     * Final witness amounts: the caller adds each side's reserved CKB on non-UDT channels before calling.
     */
    localAmountShannons: bigint;
    remoteAmountShannons: bigint;
    tlcs: SettlementTlc[];
};

/**
 * Port of fiber's `settlement_data_to_witness`: the byte string whose blake160 the commitment lock args commit to.
 * @param keys The channel's four secrets, source of the local settlement and per-TLC keys.
 * @param input The witness inputs as the node attached them.
 * @returns The `73 + 85n` witness bytes.
 */
export function buildSettlementWitness(keys: FiberChannelKeys, input: SettlementWitnessInput): Uint8Array {
    const { forRemote, remoteTlcBasePubkey, localAmountShannons, remoteAmountShannons, tlcs } = input;
    assertBytes("remoteTlcBasePubkey", remoteTlcBasePubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("localAmountShannons", localAmountShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("remoteAmountShannons", remoteAmountShannons, MAX_AMOUNT_SHANNONS);
    if (!Array.isArray(tlcs) || tlcs.length > MAX_SETTLEMENT_TLCS) {
        throw new TypeError(`tlcs must be an array of at most ${MAX_SETTLEMENT_TLCS} TLCs`);
    }

    const records = orderTlcs(tlcs, forRemote).map((tlc) => buildTlcRecord(keys, tlc, forRemote, remoteTlcBasePubkey));
    const localHash = blake160(pubkeyOf(keys.tlcBaseKey));
    const remoteHash = blake160(remoteTlcBasePubkey);
    const localBlock = concatBytes(localHash, uint128Le(localAmountShannons));
    const remoteBlock = concatBytes(remoteHash, uint128Le(remoteAmountShannons));
    const blocks = forRemote ? [remoteBlock, localBlock] : [localBlock, remoteBlock];
    return concatBytes(Uint8Array.of(records.length), ...records, ...blocks);
}

/**
 * Orders the TLCs as fiber's `get_active_tlcs` does: two direction groups, each ascending by id.
 * @param tlcs TLCs to order.
 * @param forRemote Direction of the witness; it decides which group goes first.
 * @returns The ordered TLCs.
 */
function orderTlcs(tlcs: SettlementTlc[], forRemote: boolean): SettlementTlc[] {
    const firstGroup: TlcDirection = forRemote ? "received" : "offered";
    /**
     * Compares two TLCs by numeric id.
     * @param a First TLC.
     * @param b Second TLC.
     * @returns Negative when `a` sorts first.
     */
    const byId = (a: SettlementTlc, b: SettlementTlc): number => a.id - b.id;
    const first = tlcs.filter((tlc) => tlc.direction === firstGroup).sort(byId);
    const second = tlcs.filter((tlc) => tlc.direction !== firstGroup).sort(byId);
    return [...first, ...second];
}

/**
 * Port of fiber's `settlement_tlc_to_witness`: one 85-byte TLC record.
 * @param keys The channel's four secrets, source of the local per-TLC key.
 * @param tlc The TLC to serialize.
 * @param forRemote Direction of the witness; it flips the direction flag and swaps the key hashes.
 * @param remoteTlcBasePubkey The peer's TLC base pubkey its per-TLC key derives from.
 * @returns The 85 bytes.
 */
function buildTlcRecord(keys: FiberChannelKeys, tlc: SettlementTlc, forRemote: boolean, remoteTlcBasePubkey: Uint8Array): Uint8Array {
    assertUnsignedInteger("tlc.id", tlc.id, Number.MAX_SAFE_INTEGER);
    assertUnsignedBigInt("tlc.amountShannons", tlc.amountShannons, MAX_AMOUNT_SHANNONS);
    assertBytes("tlc.paymentHash", tlc.paymentHash, PAYMENT_HASH_LENGTH);
    assertUnsignedBigInt("tlc.expiryMs", tlc.expiryMs, MAX_SINCE_PAYLOAD * MILLISECONDS_PER_SECOND);
    assertUnsignedInteger("tlc.createdAtRemoteCommitmentNumber", tlc.createdAtRemoteCommitmentNumber, MAX_COMMITMENT_NUMBER);
    assertBytes("tlc.remoteCommitmentPoint", tlc.remoteCommitmentPoint, COMPRESSED_POINT_LENGTH);
    if (tlc.direction !== "offered" && tlc.direction !== "received") {
        throw new TypeError("tlc.direction must be offered or received");
    }
    if (!(tlc.hashAlgorithm in HASH_ALGORITHM_BITS)) {
        throw new TypeError(`tlc.hashAlgorithm must be one of ${Object.keys(HASH_ALGORITHM_BITS).join(", ")}`);
    }

    // A for_remote=false witness flips every TLC id (fiber's flip_mut), which only shows up here, in the flag bit.
    const offeredBit = (tlc.direction === "offered") === forRemote ? 0 : 1;
    const flag = (HASH_ALGORITHM_BITS[tlc.hashAlgorithm] << 1) | offeredBit;
    const localHash = blake160(pubkeyOf(deriveTlcKey(keys, tlc.createdAtRemoteCommitmentNumber)));
    const remoteHash = blake160(derivePublicKey(remoteTlcBasePubkey, tlc.remoteCommitmentPoint));
    const keyHashes = forRemote ? [remoteHash, localHash] : [localHash, remoteHash];
    const since = SINCE_ABSOLUTE_TIMESTAMP_FLAG | (tlc.expiryMs / MILLISECONDS_PER_SECOND);
    return concatBytes(
        Uint8Array.of(flag),
        uint128Le(tlc.amountShannons),
        tlc.paymentHash.slice(0, TRUNCATED_PAYMENT_HASH_LENGTH),
        ...keyHashes,
        uint64Le(since),
    );
}
