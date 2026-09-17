import { isNonEmptyString, isPlainObject, isUnsignedInteger } from "../common";
import { WireError } from "./wire.error";
import type { Field, FieldReader } from "./wire.types";

/**
 * Refuses a field, ending the decode wherever it is.
 * @param field Field that failed.
 * @param reason What the field had to be.
 */
export function malformed(field: Field, reason: string): never {
    throw new WireError(field.path, reason);
}

/**
 * Reads a field as a plain object, refusing anything else.
 * @param field Field to read.
 * @returns The object, still unknown member by member.
 */
export function requireObject(field: Field): Record<string, unknown> {
    if (!isPlainObject(field.value)) malformed(field, "must be an object");
    return field.value;
}

/**
 * Reads a field as an object whose members a wire type names, so a decoder cannot read a member the wire does not spell.
 * @param field Field to read.
 * @returns A reader of the object's members, each a field of its own.
 */
export function readObject<Wire extends object>(field: Field): FieldReader<Wire> {
    const record = requireObject(field);
    return (name) => ({ value: record[name], path: `${field.path}.${name}` });
}

/**
 * Reads a field as an array, of an exact length when the wire fixes one.
 * @param field Field to read.
 * @param length Exact number of items, or `undefined` for any number.
 * @returns The items, each a field of its own.
 */
export function readArray(field: Field, length?: number): Field[] {
    if (!Array.isArray(field.value)) malformed(field, "must be an array");
    const items: unknown[] = field.value;
    if (length !== undefined && items.length !== length) malformed(field, `must have exactly ${length} items`);
    // Array.from visits holes too, which map skips: a sparse array cannot come from JSON, but an item must never go unread.
    return Array.from(items, (value, index) => ({ value, path: `${field.path}[${index}]` }));
}

/**
 * Reads a field as an array of exactly two items.
 * @param field Field to read.
 * @returns The two items, each a field of its own.
 */
export function readPair(field: Field): [Field, Field] {
    const [first, second] = readArray(field, 2);
    return [first as Field, second as Field];
}

/**
 * Reads a field as a JSON boolean.
 * @param field Field to read.
 * @returns The boolean.
 */
export function decodeBoolean(field: Field): boolean {
    if (typeof field.value !== "boolean") malformed(field, "must be a boolean");
    return field.value;
}

/**
 * Reads a field as a JSON string, empty included.
 * @param field Field to read.
 * @returns The string.
 */
export function decodeString(field: Field): string {
    if (typeof field.value !== "string") malformed(field, "must be a string");
    return field.value;
}

/**
 * Reads a field as a JSON string with at least one character.
 * @param field Field to read.
 * @returns The string.
 */
export function decodeNonEmptyString(field: Field): string {
    if (!isNonEmptyString(field.value)) malformed(field, "must be a non-empty string");
    return field.value;
}

/**
 * Reads a field as one of a closed set of string values.
 * @param field Field to read.
 * @param values The accepted values.
 * @returns The value, narrowed to the set.
 */
export function decodeEnum<Values extends readonly string[]>(field: Field, values: Values): Values[number] {
    const accepted: readonly string[] = values;
    if (typeof field.value !== "string" || !accepted.includes(field.value)) malformed(field, `must be one of ${values.join(", ")}`);
    return field.value;
}

/**
 * Reads a field as a key of a wire-to-SDK spelling map and returns the SDK spelling.
 * @param field Field to read.
 * @param spellings Wire spelling to SDK spelling.
 * @returns The SDK spelling.
 */
export function decodeMapped<Spellings extends Record<string, string>>(field: Field, spellings: Spellings): Spellings[keyof Spellings] {
    const key = decodeEnum(field, Object.keys(spellings));
    return spellings[key] as Spellings[keyof Spellings];
}

/**
 * Reads a field as a JSON number that is an integer within `[0, max]`.
 * @param field Field to read.
 * @param max Highest accepted value, inclusive.
 * @returns The integer.
 */
export function decodeUnsignedInteger(field: Field, max: number): number {
    if (!isUnsignedInteger(field.value, max)) malformed(field, `must be an integer between 0 and ${max}`);
    return field.value;
}
