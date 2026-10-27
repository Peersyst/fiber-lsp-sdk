import { equalBytes } from "@noble/curves/utils.js";
import { keyAggExport, keyAggregate } from "@scure/btc-signer/musig2.js";
import { assertCompressedPoint, assertUnsignedBigInt, compareBytes, uint128Le } from "../../common";
import { MAX_CAPACITY_SHANNONS } from "../digest.constants";
import type { CommitmentTxInput } from "../digest.types";

export type CommitmentCellValue = {
    capacityShannons: bigint;
    /**
     * The liquid capacity as a UDT amount on a UDT channel, empty on a CKB one.
     */
    data: Uint8Array;
};

/**
 * Aggregates two pubkeys in the order given into the x-only key fiber bakes into lock args.
 * @param orderedPubkeys The two compressed keys, order-sensitive.
 * @returns The x-only aggregate.
 */
export function aggregateXOnlyPubkey(orderedPubkeys: [Uint8Array, Uint8Array]): Uint8Array {
    return keyAggExport(keyAggregate(orderedPubkeys));
}

/**
 * Sorts two distinct compressed pubkeys ascending by their bytes, the order fiber gives the two parties' keys.
 * @param firstName Name of the first key, for the error messages.
 * @param first The first key.
 * @param secondName Name of the second key, for the error messages.
 * @param second The second key.
 * @returns The two keys, the lower first.
 */
export function sortDistinctPubkeys(firstName: string, first: unknown, secondName: string, second: unknown): [Uint8Array, Uint8Array] {
    assertCompressedPoint(firstName, first);
    assertCompressedPoint(secondName, second);
    if (equalBytes(first, second)) throw new TypeError(`${firstName} and ${secondName} must be two distinct public keys`);
    return compareBytes(first, second) < 0 ? [first, second] : [second, first];
}

/**
 * Subtracts a fee with fiber's checked semantics: a u64 overflow of the total and an underflow both refuse.
 * @param total The capacity.
 * @param fee The fee.
 * @returns The remaining capacity.
 */
export function subtractTxFee(total: bigint, fee: bigint): bigint {
    assertUnsignedBigInt("total capacity", total, MAX_CAPACITY_SHANNONS);
    if (fee > total) {
        throw new RangeError(`capacity ${total} cannot cover the fee ${fee}`);
    }
    return total - fee;
}

/**
 * The commitment cell's capacity and data, which a revocation's punishment output repeats.
 * @param input The liquid capacity, the reserves and the UDT.
 * @param fee The commitment fee.
 * @returns The capacity and raw data.
 */
export function commitmentCellValue(
    input: Pick<CommitmentTxInput, "udtTypeScript" | "liquidCapacityShannons" | "localReservedCkbShannons" | "remoteReservedCkbShannons">,
    fee: bigint,
): CommitmentCellValue {
    const { liquidCapacityShannons } = input;
    const totalReserved = input.localReservedCkbShannons + input.remoteReservedCkbShannons;
    // UDT: reserves as capacity, the liquid amount as data. CKB: both as capacity.
    return input.udtTypeScript === null
        ? { capacityShannons: subtractTxFee(liquidCapacityShannons + totalReserved, fee), data: new Uint8Array(0) }
        : { capacityShannons: subtractTxFee(totalReserved, fee), data: uint128Le(liquidCapacityShannons) };
}
