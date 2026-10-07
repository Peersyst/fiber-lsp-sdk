import { concatBytes } from "@noble/hashes/utils.js";
import {
    SCRIPT_HASH_TYPE_BYTES,
    UINT128_LENGTH,
    UINT128_MAX,
    UINT32_LENGTH,
    UINT32_MAX,
    UINT64_LENGTH,
    UINT64_MAX,
} from "../common.constants";
import type { Script } from "../common.types";
import { assertScript, assertUnsignedBigInt, assertUnsignedInteger } from "./assert.utils";

/**
 * Serializes a molecule `Uint32`, little-endian.
 * @param value Value to serialize.
 * @returns The 4 bytes.
 */
export function uint32Le(value: number): Uint8Array {
    assertUnsignedInteger("uint32 value", value, UINT32_MAX);
    const bytes = new Uint8Array(UINT32_LENGTH);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
}

/**
 * Serializes a molecule `Uint64`, little-endian.
 * @param value Value to serialize.
 * @returns The 8 bytes.
 */
export function uint64Le(value: bigint): Uint8Array {
    assertUnsignedBigInt("uint64 value", value, UINT64_MAX);
    const bytes = new Uint8Array(UINT64_LENGTH);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
}

/**
 * Serializes a molecule `Uint128`, little-endian.
 * @param value Value to serialize.
 * @returns The 16 bytes.
 */
export function uint128Le(value: bigint): Uint8Array {
    assertUnsignedBigInt("uint128 value", value, UINT128_MAX);
    const bytes = new Uint8Array(UINT128_LENGTH);
    const view = new DataView(bytes.buffer);
    view.setBigUint64(0, value & 0xffffffffffffffffn, true);
    view.setBigUint64(8, value >> 64n, true);
    return bytes;
}

/**
 * Serializes a molecule `table`: total size, one offset per field, then the field bodies.
 * @param fields Serialized field bodies, in schema order.
 * @returns The table bytes.
 */
export function moleculeTable(fields: Uint8Array[]): Uint8Array {
    const headerLength = UINT32_LENGTH * (fields.length + 1);
    const totalLength = headerLength + fields.reduce((sum, field) => sum + field.length, 0);
    const parts = [uint32Le(totalLength)];
    let offset = headerLength;
    for (const field of fields) {
        parts.push(uint32Le(offset));
        offset += field.length;
    }
    return concatBytes(...parts, ...fields);
}

/**
 * Serializes a molecule `fixvec`: item count, then the items; items must share one fixed size.
 * @param items Serialized items.
 * @returns The fixvec bytes.
 */
export function moleculeFixvec(items: Uint8Array[]): Uint8Array {
    return concatBytes(uint32Le(items.length), ...items);
}

/**
 * Serializes a molecule `dynvec`: total size and one offset per item, or a bare 4-byte size when empty.
 * @param items Serialized items.
 * @returns The dynvec bytes.
 */
export function moleculeDynvec(items: Uint8Array[]): Uint8Array {
    return items.length === 0 ? uint32Le(UINT32_LENGTH) : moleculeTable(items);
}

/**
 * Serializes a molecule `Bytes`: a fixvec of bytes, so a length prefix and the raw data.
 * @param data Raw data to wrap.
 * @returns The Bytes bytes.
 */
export function moleculeBytes(data: Uint8Array): Uint8Array {
    return concatBytes(uint32Le(data.length), data);
}

/**
 * Serializes a molecule `Script` table.
 * @param script Script to serialize.
 * @param name Its path, used in the error message.
 * @returns The Script bytes.
 */
export function moleculeScript(script: Script, name = "script"): Uint8Array {
    assertScript(name, script);
    return moleculeTable([script.codeHash, Uint8Array.of(SCRIPT_HASH_TYPE_BYTES[script.hashType]), moleculeBytes(script.args)]);
}

/**
 * Serializes a molecule `ScriptOpt`: the script's bytes, or zero bytes for `null`.
 * @param script Script to serialize, or `null` for none.
 * @returns The ScriptOpt bytes.
 */
export function moleculeScriptOpt(script: Script | null): Uint8Array {
    return script === null ? new Uint8Array(0) : moleculeScript(script);
}
