import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { assertAnyBytes, assertBytes, isHexBytes } from "../common";
import { malformed } from "./field";
import { WIRE_HEX_PREFIX } from "./wire.constants";
import type { BareHexWire, Field, HexWire } from "./wire.types";

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
 * Writes bytes of an exact length as wire hex.
 * @param name Name of the value, used in the error message.
 * @param bytes Bytes to write.
 * @param byteLength Exact number of bytes the value must have.
 * @returns The `0x`-prefixed lowercase hex.
 */
export function encodeHexBytes(name: string, bytes: Uint8Array, byteLength: number): HexWire {
    assertBytes(name, bytes, byteLength);
    return WIRE_HEX_PREFIX + bytesToHex(bytes);
}

/**
 * Writes bytes of any length as wire hex, `0x` for none.
 * @param name Name of the value, used in the error message.
 * @param bytes Bytes to write.
 * @returns The `0x`-prefixed lowercase hex.
 */
export function encodeAnyHexBytes(name: string, bytes: Uint8Array): HexWire {
    assertAnyBytes(name, bytes);
    return WIRE_HEX_PREFIX + bytesToHex(bytes);
}

/**
 * Reads a field as lowercase hex of an exact length without the `0x` prefix.
 * @param field Field to read.
 * @param byteLength Exact number of bytes the hex must encode.
 * @returns The bytes.
 */
export function decodeBareHexBytes(field: Field, byteLength: number): Uint8Array {
    if (!isHexBytes(field.value, byteLength)) malformed(field, `must be ${byteLength} bytes of lowercase hex without a 0x prefix`);
    return hexToBytes(field.value);
}

/**
 * Writes bytes of an exact length as lowercase hex without the `0x` prefix.
 * @param name Name of the value, used in the error message.
 * @param bytes Bytes to write.
 * @param byteLength Exact number of bytes the value must have.
 * @returns The bare hex.
 */
export function encodeBareHexBytes(name: string, bytes: Uint8Array, byteLength: number): BareHexWire {
    assertBytes(name, bytes, byteLength);
    return bytesToHex(bytes);
}

/**
 * Asserts that a value is wire hex of an exact length.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 * @param byteLength Exact number of bytes the hex must encode.
 */
export function assertWireHexBytes(name: string, value: unknown, byteLength: number): asserts value is string {
    if (!isWireHex(value, byteLength)) {
        throw new TypeError(`${name} must be ${byteLength} bytes of 0x-prefixed lowercase hex`);
    }
}
