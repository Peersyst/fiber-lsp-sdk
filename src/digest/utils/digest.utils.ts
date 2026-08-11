import { keyAggExport, keyAggregate } from "@scure/btc-signer/musig2.js";
import { assertUnsignedBigInt } from "../../common";
import { MAX_CAPACITY_SHANNONS } from "../digest.constants";

/**
 * Aggregates two pubkeys in the exact order given and returns the x-only aggregate, the key fiber bakes into lock args.
 * @param orderedPubkeys The two 33-byte compressed keys, order-sensitive.
 * @returns The 32-byte x-only aggregated key.
 */
export function aggregateXOnlyPubkey(orderedPubkeys: [Uint8Array, Uint8Array]): Uint8Array {
    return keyAggExport(keyAggregate(orderedPubkeys));
}

/**
 * Subtracts a fee from a capacity with fiber's checked semantics: u64 overflow of the total and underflow both refuse.
 * @param total Capacity the fee comes out of, in shannons.
 * @param fee Fee to subtract, in shannons.
 * @returns The remaining capacity.
 */
export function subtractFee(total: bigint, fee: bigint): bigint {
    assertUnsignedBigInt("total capacity", total, MAX_CAPACITY_SHANNONS);
    if (fee > total) {
        throw new RangeError(`capacity ${total} cannot cover the fee ${fee}`);
    }
    return total - fee;
}
