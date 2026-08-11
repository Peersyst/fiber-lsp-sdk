import { concatBytes } from "@noble/hashes/utils.js";
import { MAX_AMOUNT_SHANNONS, assertBytes, assertUnsignedBigInt, assertUnsignedInteger } from "../../common";
import { CELL_DEP_LENGTH, CELL_INPUT_LENGTH, MAX_CAPACITY_SHANNONS } from "../digest.constants";
import type { OutPoint, Script, ScriptHashType } from "../digest.types";

const U32_MAX = 2 ** 32 - 1;
const U32_LENGTH = 4;
const BYTE32_LENGTH = 32;

/**
 * The molecule `hash_type` byte: `DataN` encodes as `N << 1`, `type` as 1.
 */
const HASH_TYPE_BYTES: Record<ScriptHashType, number> = { data: 0, type: 1, data1: 2, data2: 4 };

/**
 * Serializes a molecule `Uint32`, little-endian.
 * @param value Value to serialize.
 * @returns The 4 bytes.
 */
export function uint32Le(value: number): Uint8Array {
    assertUnsignedInteger("uint32 value", value, U32_MAX);
    const bytes = new Uint8Array(U32_LENGTH);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
}

/**
 * Serializes a molecule `Uint64`, little-endian.
 * @param value Value to serialize.
 * @returns The 8 bytes.
 */
export function uint64Le(value: bigint): Uint8Array {
    assertUnsignedBigInt("uint64 value", value, MAX_CAPACITY_SHANNONS);
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
}

/**
 * Serializes a molecule `Uint64`, big-endian, the byte order of the commitment number in lock args.
 * @param value Value to serialize.
 * @returns The 8 bytes.
 */
export function uint64Be(value: bigint): Uint8Array {
    assertUnsignedBigInt("uint64 value", value, MAX_CAPACITY_SHANNONS);
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}

/**
 * Serializes a molecule `Uint128`, little-endian.
 * @param value Value to serialize.
 * @returns The 16 bytes.
 */
export function uint128Le(value: bigint): Uint8Array {
    assertUnsignedBigInt("uint128 value", value, MAX_AMOUNT_SHANNONS);
    const bytes = new Uint8Array(16);
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
    const headerLength = U32_LENGTH * (fields.length + 1);
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
    if (items.length === 0) return uint32Le(U32_LENGTH);
    const headerLength = U32_LENGTH * (items.length + 1);
    const totalLength = headerLength + items.reduce((sum, item) => sum + item.length, 0);
    const parts = [uint32Le(totalLength)];
    let offset = headerLength;
    for (const item of items) {
        parts.push(uint32Le(offset));
        offset += item.length;
    }
    return concatBytes(...parts, ...items);
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
 * @returns The Script bytes.
 */
export function encodeScript(script: Script): Uint8Array {
    assertBytes("script.codeHash", script.codeHash, BYTE32_LENGTH);
    if (!(script.hashType in HASH_TYPE_BYTES)) {
        throw new TypeError(`script.hashType must be one of ${Object.keys(HASH_TYPE_BYTES).join(", ")}`);
    }
    if (!(script.args instanceof Uint8Array)) {
        throw new TypeError("script.args must be a Uint8Array");
    }
    return moleculeTable([script.codeHash, Uint8Array.of(HASH_TYPE_BYTES[script.hashType]), moleculeBytes(script.args)]);
}

/**
 * Serializes a molecule `ScriptOpt`: the script's bytes, or zero bytes for `null`.
 * @param script Script to serialize, or `null` for none.
 * @returns The ScriptOpt bytes.
 */
export function encodeScriptOpt(script: Script | null): Uint8Array {
    return script === null ? new Uint8Array(0) : encodeScript(script);
}

/**
 * Serializes a molecule `OutPoint` struct.
 * @param outPoint Out point to serialize.
 * @returns The 36 bytes.
 */
export function encodeOutPoint(outPoint: OutPoint): Uint8Array {
    assertBytes("outPoint.txHash", outPoint.txHash, BYTE32_LENGTH);
    assertUnsignedInteger("outPoint.index", outPoint.index, U32_MAX);
    return concatBytes(outPoint.txHash, uint32Le(outPoint.index));
}

/**
 * Serializes a molecule `CellInput` struct.
 * @param since The input's since bound.
 * @param previousOutput The consumed cell's out point.
 * @returns The 44 bytes.
 */
export function encodeCellInput(since: bigint, previousOutput: OutPoint): Uint8Array {
    return concatBytes(uint64Le(since), encodeOutPoint(previousOutput));
}

/**
 * Serializes a molecule `CellOutput` table.
 * @param capacity Capacity in shannons.
 * @param lock Lock script of the cell.
 * @param type Type script of the cell, or `null` for none.
 * @returns The CellOutput bytes.
 */
export function encodeCellOutput(capacity: bigint, lock: Script, type: Script | null): Uint8Array {
    return moleculeTable([uint64Le(capacity), encodeScript(lock), encodeScriptOpt(type)]);
}

export type RawTransactionFields = {
    version: number;
    /**
     * Serialized 37-byte CellDeps; the digest always passes none, fee sizing passes zeroed mocks.
     */
    cellDeps: Uint8Array[];
    headerDeps: Uint8Array[];
    /**
     * Serialized 44-byte CellInputs.
     */
    inputs: Uint8Array[];
    /**
     * Serialized CellOutputs.
     */
    outputs: Uint8Array[];
    /**
     * Raw per-output data, wrapped into molecule `Bytes` here.
     */
    outputsData: Uint8Array[];
};

/**
 * Serializes a molecule `RawTransaction` table, the exact bytes fiber's `compute_tx_message` hashes.
 * @param fields The six schema fields.
 * @returns The RawTransaction bytes.
 */
export function encodeRawTransaction(fields: RawTransactionFields): Uint8Array {
    for (const [index, cellDep] of fields.cellDeps.entries()) assertBytes(`cellDeps[${index}]`, cellDep, CELL_DEP_LENGTH);
    for (const [index, headerDep] of fields.headerDeps.entries()) assertBytes(`headerDeps[${index}]`, headerDep, BYTE32_LENGTH);
    for (const [index, input] of fields.inputs.entries()) assertBytes(`inputs[${index}]`, input, CELL_INPUT_LENGTH);
    return moleculeTable([
        uint32Le(fields.version),
        moleculeFixvec(fields.cellDeps),
        moleculeFixvec(fields.headerDeps),
        moleculeFixvec(fields.inputs),
        moleculeDynvec(fields.outputs),
        moleculeDynvec(fields.outputsData.map(moleculeBytes)),
    ]);
}

/**
 * Serializes a molecule `Transaction` table, needed whole only to measure fee-sizing mocks.
 * @param raw The serialized RawTransaction.
 * @param witnesses Raw witnesses, wrapped into molecule `Bytes` here.
 * @returns The Transaction bytes.
 */
export function encodeTransaction(raw: Uint8Array, witnesses: Uint8Array[]): Uint8Array {
    return moleculeTable([raw, moleculeDynvec(witnesses.map(moleculeBytes))]);
}
