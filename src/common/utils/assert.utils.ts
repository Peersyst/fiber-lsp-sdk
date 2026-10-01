import { isDecimalShannons, isHexBytes, isNonEmptyString, isUnsignedInteger } from "./validate.utils";

/**
 * Asserts that a value is a byte array, of any length.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertAnyBytes(name: string, value: unknown): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`${name} must be a Uint8Array`);
    }
}

/**
 * Asserts that a value is a byte array of an exact length.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param length Exact length the value must have, in bytes.
 */
export function assertBytes(name: string, value: unknown, length: number): asserts value is Uint8Array {
    assertAnyBytes(name, value);
    if (value.length !== length) {
        throw new TypeError(`${name} must be ${length} bytes, got ${value.length}`);
    }
}

/**
 * Asserts that a value is an integer within `[0, max]`.
 * @param name Name of the value, used in the error message.
 * @param value Value to check, which an optional field may leave absent.
 * @param max Highest accepted value, inclusive.
 */
export function assertUnsignedInteger(name: string, value: unknown, max: number): asserts value is number {
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
 * Asserts that a value is a string, empty included.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertString(name: string, value: unknown): asserts value is string {
    if (typeof value !== "string") {
        throw new TypeError(`${name} must be a string`);
    }
}

/**
 * Asserts that a value is a non-empty string.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertNonEmptyString(name: string, value: string): void {
    if (!isNonEmptyString(value)) {
        throw new TypeError(`${name} must be a non-empty string`);
    }
}

/**
 * Asserts that a value is an amount in decimal shannons.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertDecimalShannons(name: string, value: string): void {
    if (!isDecimalShannons(value)) {
        throw new TypeError(`${name} must be an amount in decimal shannons`);
    }
}

/**
 * Asserts that a value is a boolean.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertBoolean(name: string, value: unknown): asserts value is boolean {
    if (typeof value !== "boolean") {
        throw new TypeError(`${name} must be a boolean`);
    }
}

/**
 * Asserts that a value is one of a closed set of string values.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param values The accepted values.
 */
export function assertOneOf<Values extends readonly string[]>(
    name: string,
    value: unknown,
    values: Values,
): asserts value is Values[number] {
    const accepted: readonly string[] = values;
    if (typeof value !== "string" || !accepted.includes(value)) {
        throw new TypeError(`${name} must be one of ${values.join(", ")}`);
    }
}
