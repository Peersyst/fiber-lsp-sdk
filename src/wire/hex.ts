import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { malformed } from "./field";
import { WIRE_HEX_PREFIX } from "./wire.constants";
import type { Field } from "./wire.types";

const HEX_BYTES_PATTERN = /^0x(?:[0-9a-f]{2})*$/;

/**
 * Checks that a value is `0x`-prefixed lowercase hex encoding whole bytes, exactly `byteLength` of them when given.
 * @param value Value to check.
 * @param byteLength Exact number of bytes, or `undefined` for any number.
 * @returns Whether the value is wire hex of that size.
 */
export function isWireHex(value: unknown, byteLength?: number): value is string {
    if (typeof value !== "string" || !HEX_BYTES_PATTERN.test(value)) return false;
    return byteLength === undefined || value.length === WIRE_HEX_PREFIX.length + byteLength * 2;
}

/**
 * Reads a field as wire hex of an exact length, keeping the wire string.
 * @param field Field to read.
 * @param byteLength Exact number of bytes the hex must encode.
 * @returns The wire string, validated.
 */
export function requireHexBytes(field: Field, byteLength: number): string {
    if (!isWireHex(field.value, byteLength)) malformed(field, `must be ${byteLength} bytes of 0x-prefixed lowercase hex`);
    return field.value;
}

/**
 * Reads a field as wire hex of an exact length.
 * @param field Field to read.
 * @param byteLength Exact number of bytes the hex must encode.
 * @returns The bytes.
 */
export function decodeHexBytes(field: Field, byteLength: number): Uint8Array {
    return hexToBytes(requireHexBytes(field, byteLength).slice(WIRE_HEX_PREFIX.length));
}

/**
 * Reads a field as wire hex of any length, `0x` included, the form of script args.
 * @param field Field to read.
 * @returns The bytes.
 */
export function decodeAnyHexBytes(field: Field): Uint8Array {
    if (!isWireHex(field.value)) malformed(field, "must be whole bytes of 0x-prefixed lowercase hex");
    return hexToBytes(field.value.slice(WIRE_HEX_PREFIX.length));
}

/**
 * Writes bytes as wire hex.
 * @param bytes Bytes to write.
 * @returns The `0x`-prefixed lowercase hex.
 */
export function encodeHexBytes(bytes: Uint8Array): string {
    return WIRE_HEX_PREFIX + bytesToHex(bytes);
}
