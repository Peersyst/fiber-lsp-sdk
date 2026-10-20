import { equalBytes } from "@noble/curves/utils.js";
import { COMPRESSED_POINT_LENGTH, MUSIG_PARTICIPANTS } from "../common.constants";
import { assertBytes } from "./assert.utils";
import { isCompressedPoint } from "./validate.utils";

/**
 * Splits a 66-byte musig2 nonce into its two compressed points.
 * @param nonce The nonce, public or aggregated.
 * @returns The two 33-byte halves, views over the nonce.
 */
export function nonceHalves(nonce: Uint8Array): [Uint8Array, Uint8Array] {
    return [nonce.subarray(0, COMPRESSED_POINT_LENGTH), nonce.subarray(COMPRESSED_POINT_LENGTH, 2 * COMPRESSED_POINT_LENGTH)];
}

/**
 * Checks that a half of an aggregated nonce is a point on the curve or BIP-327's `cbytes_ext` of infinity, 33 zero bytes.
 * @param half Value to check.
 * @returns Whether musig2 can write it as a half of an aggregate.
 */
export function isAggregatedNonceHalf(half: unknown): half is Uint8Array {
    if (isCompressedPoint(half)) return true;
    return half instanceof Uint8Array && half.length === COMPRESSED_POINT_LENGTH && half.every((byte) => byte === 0);
}

/**
 * Asserts that a musig2 key list is two distinct 33-byte keys.
 * @param name Name for the error messages.
 * @param keys Value to check.
 * @returns The two keys, in the order of the list.
 */
export function assertTwoDistinctKeys(name: string, keys: unknown): [Uint8Array, Uint8Array] {
    if (!Array.isArray(keys) || keys.length !== MUSIG_PARTICIPANTS) {
        throw new TypeError(`${name} must be exactly ${MUSIG_PARTICIPANTS} public keys`);
    }
    const [firstKey, secondKey]: unknown[] = keys;
    assertBytes(`${name}[0]`, firstKey, COMPRESSED_POINT_LENGTH);
    assertBytes(`${name}[1]`, secondKey, COMPRESSED_POINT_LENGTH);
    if (equalBytes(firstKey, secondKey)) {
        throw new TypeError(`${name} must be two distinct public keys`);
    }
    return [firstKey, secondKey];
}
