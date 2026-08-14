import { MAX_AMOUNT_SHANNONS } from "../common.constants";

const CANONICAL_DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const LOWERCASE_HEX_PATTERN = /^[0-9a-f]*$/;
// Length-checked before converting to BigInt, so a megabyte of digits costs nothing.
const MAX_AMOUNT_DIGITS = MAX_AMOUNT_SHANNONS.toString().length;

/**
 * Checks that a value is a non-null object that is not an array, the shape external JSON must have to be read field by field.
 * @param value Value to check.
 * @returns Whether the value can be read as a record of unknown fields.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Checks that a value is an integer within `[0, max]`.
 * @param value Value to check.
 * @param max Highest accepted value, inclusive.
 * @returns Whether the value is an unsigned integer within the bound.
 */
export function isUnsignedInteger(value: unknown, max: number): value is number {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

/**
 * Checks that a string is canonical decimal digits: no sign, no leading zeros, so one value has one representation.
 * @param value Value to check.
 * @returns Whether the string is a canonical decimal integer.
 */
export function isCanonicalDecimal(value: string): boolean {
    return CANONICAL_DECIMAL_PATTERN.test(value);
}

/**
 * Checks that a value is a string with at least one character.
 * @param value Value to check.
 * @returns Whether the value is a non-empty string.
 */
export function isNonEmptyString(value: unknown): value is string {
    return typeof value === "string" && value.length > 0;
}

/**
 * Checks that a value is lowercase hex encoding exactly `byteLength` bytes.
 * @param value Value to check.
 * @param byteLength Exact number of bytes the hex must encode.
 * @returns Whether the value is a lowercase hex string of that size.
 */
export function isHexBytes(value: unknown, byteLength: number): value is string {
    return typeof value === "string" && value.length === byteLength * 2 && LOWERCASE_HEX_PATTERN.test(value);
}

/**
 * Checks that a value is an amount in decimal shannons: canonical digits within fiber's u128 range, no sign, no leading zeros.
 * @param value Value to check.
 * @returns Whether the value is a decimal shannons string.
 */
export function isDecimalShannons(value: unknown): value is string {
    return (
        typeof value === "string" && value.length <= MAX_AMOUNT_DIGITS && isCanonicalDecimal(value) && BigInt(value) <= MAX_AMOUNT_SHANNONS
    );
}
