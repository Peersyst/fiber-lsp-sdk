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
 * Checks that a value is lowercase hex encoding exactly `byteLength` bytes.
 * @param value Value to check.
 * @param byteLength Exact number of bytes the hex must encode.
 * @returns Whether the value is a lowercase hex string of that size.
 */
export function isHexBytes(value: unknown, byteLength: number): value is string {
    return typeof value === "string" && value.length === byteLength * 2 && /^[0-9a-f]*$/.test(value);
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
