import { isHexBytes, isUnsignedInteger } from "./validate.utils";

/**
 * Asserts that a value is a byte array of an exact length.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param length Exact length the value must have, in bytes.
 */
export function assertBytes(name: string, value: unknown, length: number): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`${name} must be a Uint8Array`);
    }
    if (value.length !== length) {
        throw new TypeError(`${name} must be ${length} bytes, got ${value.length}`);
    }
}

/**
 * Asserts that a value is an integer within `[0, max]`.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param max Highest accepted value, inclusive.
 */
export function assertUnsignedInteger(name: string, value: number, max: number): void {
    if (!isUnsignedInteger(value, max)) {
        throw new RangeError(`${name} must be an integer between 0 and ${max}, got ${value}`);
    }
}

/**
 * Asserts that a value is a bigint within `[0, max]`.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param max Highest accepted value, inclusive.
 */
export function assertUnsignedBigInt(name: string, value: bigint, max: bigint): void {
    if (typeof value !== "bigint" || value < 0n || value > max) {
        throw new RangeError(`${name} must be a bigint between 0 and ${max}, got ${value}`);
    }
}

/**
 * Asserts that a value is lowercase hex encoding exactly `byteLength` bytes.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param byteLength Exact number of bytes the hex must encode.
 */
export function assertHexBytes(name: string, value: string, byteLength: number): void {
    if (!isHexBytes(value, byteLength)) {
        // Never echo the value: it may be a secret.
        throw new TypeError(`${name} must be ${byteLength} bytes of lowercase hex`);
    }
}

/**
 * Asserts that a value is a non-empty string.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertNonEmptyString(name: string, value: string): void {
    if (typeof value !== "string" || value.length === 0) {
        throw new TypeError(`${name} must be a non-empty string`);
    }
}
