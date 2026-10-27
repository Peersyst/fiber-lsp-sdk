import { COMPRESSED_POINT_LENGTH, DEP_TYPES, HASH256_LENGTH, MAX_TIMER_DELAY_MS, SCRIPT_HASH_TYPES, UINT32_MAX } from "../common.constants";
import type { CellDep, OutPoint, Script, ScriptTemplate } from "../common.types";
import { isCompressedPoint, isDecimalShannons, isHexBytes, isNonEmptyString, isPlainObject, isUnsignedInteger } from "./validate.utils";

/**
 * Asserts that a value is a byte array, of any length.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertAnyBytes(name: string, value: unknown): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`${name} must be a Uint8Array`);
    }
}

/**
 * Asserts that a value is a byte array of an exact length.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param length Exact length in bytes.
 */
export function assertBytes(name: string, value: unknown, length: number): asserts value is Uint8Array {
    assertAnyBytes(name, value);
    if (value.length !== length) {
        throw new TypeError(`${name} must be ${length} bytes, got ${value.length}`);
    }
}

/**
 * Asserts that a value is a compressed secp256k1 point.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertCompressedPoint(name: string, value: unknown): asserts value is Uint8Array {
    assertBytes(name, value, COMPRESSED_POINT_LENGTH);
    if (!isCompressedPoint(value)) throw new TypeError(`${name} must be a compressed point on secp256k1`);
}

/**
 * Asserts that a value is an integer within `[0, max]`.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param max Highest accepted value.
 */
export function assertUnsignedInteger(name: string, value: unknown, max: number): asserts value is number {
    if (!isUnsignedInteger(value, max)) {
        throw new RangeError(`${name} must be an integer between 0 and ${max}, got ${value}`);
    }
}

/**
 * Asserts that a value is an integer within `[1, max]`.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param max Highest accepted value.
 */
export function assertPositiveInteger(name: string, value: unknown, max: number): asserts value is number {
    if (!isUnsignedInteger(value, max) || value === 0) {
        throw new RangeError(`${name} must be an integer between 1 and ${max}, got ${String(value)}`);
    }
}

/**
 * Asserts that a value is a bigint within `[0, max]`.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param max Highest accepted value.
 */
export function assertUnsignedBigInt(name: string, value: bigint, max: bigint): void {
    if (typeof value !== "bigint" || value < 0n || value > max) {
        throw new RangeError(`${name} must be a bigint between 0 and ${max}, got ${value}`);
    }
}

/**
 * Asserts that a value is lowercase hex encoding exactly `byteLength` bytes.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param byteLength Exact length in bytes.
 */
export function assertHexBytes(name: string, value: string, byteLength: number): void {
    if (!isHexBytes(value, byteLength)) {
        // Never echo the value: it may be a secret.
        throw new TypeError(`${name} must be ${byteLength} bytes of lowercase hex`);
    }
}

/**
 * Asserts that a value is a function.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertFunction(name: string, value: unknown): asserts value is (...args: never[]) => unknown {
    if (typeof value !== "function") throw new TypeError(`${name} must be a function`);
}

/**
 * Asserts that a value is a string, empty included.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertString(name: string, value: unknown): asserts value is string {
    if (typeof value !== "string") {
        throw new TypeError(`${name} must be a string`);
    }
}

/**
 * Asserts that a value is a non-empty string.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertNonEmptyString(name: string, value: string): void {
    if (!isNonEmptyString(value)) {
        throw new TypeError(`${name} must be a non-empty string`);
    }
}

/**
 * Asserts that a value is an amount in decimal shannons.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertDecimalShannons(name: string, value: string): void {
    if (!isDecimalShannons(value)) {
        throw new TypeError(`${name} must be an amount in decimal shannons`);
    }
}

/**
 * Asserts that a value is a boolean.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertBoolean(name: string, value: unknown): asserts value is boolean {
    if (typeof value !== "boolean") {
        throw new TypeError(`${name} must be a boolean`);
    }
}

/**
 * Asserts that a value is one of a closed set of string values.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param values Accepted values.
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

/**
 * Asserts that a value is a script: a 32-byte code hash, a hash type CKB defines, and args of any length.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertScript(name: string, value: unknown): asserts value is Script {
    assertScriptTemplate(name, value);
    assertAnyBytes(`${name}.args`, (value as Partial<Script>).args);
}

/**
 * Asserts that a value is a script template: a code hash and a hash type, no args.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertScriptTemplate(name: string, value: unknown): asserts value is ScriptTemplate {
    if (!isPlainObject(value)) throw new TypeError(`${name} must be an object`);
    assertBytes(`${name}.codeHash`, value.codeHash, HASH256_LENGTH);
    assertOneOf(`${name}.hashType`, value.hashType, SCRIPT_HASH_TYPES);
}

/**
 * Asserts that a timing option is a whole number of milliseconds a timer can take.
 * @param name Name for the error message.
 * @param value Value to check.
 * @param min Lowest accepted value.
 */
export function assertTimerDelayMs(name: string, value: number, min: number): void {
    if (!isUnsignedInteger(value, MAX_TIMER_DELAY_MS) || value < min) {
        throw new RangeError(`${name} must be an integer between ${min} and ${MAX_TIMER_DELAY_MS}, got ${value}`);
    }
}

/**
 * Asserts that a value is an out point: a 32-byte tx hash and an index that fits in a u32.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertOutPoint(name: string, value: unknown): asserts value is OutPoint {
    if (!isPlainObject(value)) throw new TypeError(`${name} must be an object`);
    assertBytes(`${name}.txHash`, value.txHash, HASH256_LENGTH);
    assertUnsignedInteger(`${name}.index`, value.index, UINT32_MAX);
}

/**
 * Asserts that a value is a cell dep: an out point and one of CKB's dep types.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertCellDep(name: string, value: unknown): asserts value is CellDep {
    if (!isPlainObject(value)) throw new TypeError(`${name} must be an object`);
    assertOutPoint(`${name}.outPoint`, value.outPoint);
    assertOneOf(`${name}.depType`, value.depType, DEP_TYPES);
}

/**
 * Asserts that a value is a list of cell deps, each named by its position.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertCellDeps(name: string, value: unknown): asserts value is CellDep[] {
    if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
    value.forEach((cellDep: unknown, index) => assertCellDep(`${name}[${index}]`, cellDep));
}
