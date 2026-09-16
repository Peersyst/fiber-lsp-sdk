import { UINT128_MAX, assertUnsignedInteger } from "../common";
import { malformed } from "./field";
import { WIRE_HEX_PREFIX } from "./wire.constants";
import type { Field } from "./wire.types";

const UINT_HEX_PATTERN = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;

// Length-checked before converting to BigInt, so a megabyte of digits costs nothing; the widest wire integer is a u128.
const MAX_UINT_HEX_LENGTH = WIRE_HEX_PREFIX.length + UINT128_MAX.toString(16).length;

/**
 * Reads a field as an unsigned integer in fiber's hex form: `0x`, lowercase, no leading zeros, within `[0, max]`.
 * @param field Field to read.
 * @param max Highest accepted value, inclusive: the wire width, or the domain bound when it is narrower.
 * @returns The integer.
 */
export function decodeUintHex(field: Field, max: bigint): bigint {
    const { value } = field;
    if (typeof value !== "string" || value.length > MAX_UINT_HEX_LENGTH || !UINT_HEX_PATTERN.test(value)) {
        malformed(field, "must be an unsigned integer in 0x hex without leading zeros");
    }
    const parsed = BigInt(value);
    if (parsed > max) malformed(field, `must be at most ${max}`);
    return parsed;
}

/**
 * Reads a field as an unsigned integer in fiber's hex form, for the fields the SDK keeps as a `number`.
 * @param field Field to read.
 * @param max Highest accepted value, inclusive, at most `Number.MAX_SAFE_INTEGER`.
 * @returns The integer.
 */
export function decodeUintHexNumber(field: Field, max: number): number {
    assertUnsignedInteger("max", max, Number.MAX_SAFE_INTEGER);
    return Number(decodeUintHex(field, BigInt(max)));
}
