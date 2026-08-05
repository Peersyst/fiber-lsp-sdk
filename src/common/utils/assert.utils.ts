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
    if (!Number.isSafeInteger(value) || value < 0 || value > max) {
        throw new RangeError(`${name} must be an integer between 0 and ${max}, got ${value}`);
    }
}
