import { concatBytes } from "@noble/hashes/utils.js";
import type { OutPoint, Script } from "../../common";
import {
    HASH256_LENGTH,
    UINT64_LENGTH,
    UINT64_MAX,
    assertBytes,
    assertOutPoint,
    assertUnsignedBigInt,
    moleculeBytes,
    moleculeDynvec,
    moleculeFixvec,
    moleculeScript,
    moleculeScriptOpt,
    moleculeTable,
    uint32Le,
    uint64Le,
} from "../../common";
import { CELL_DEP_LENGTH, CELL_INPUT_LENGTH } from "../digest.constants";

/**
 * Serializes a molecule `Uint64`, big-endian, the byte order of the commitment number in lock args.
 * @param value Value to serialize.
 * @returns The 8 bytes.
 */
export function uint64Be(value: bigint): Uint8Array {
    assertUnsignedBigInt("uint64 value", value, UINT64_MAX);
    const bytes = new Uint8Array(UINT64_LENGTH);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}

/**
 * Serializes a molecule `OutPoint` struct.
 * @param outPoint Out point to serialize.
 * @returns The 36 bytes.
 */
export function moleculeOutPoint(outPoint: OutPoint): Uint8Array {
    assertOutPoint("outPoint", outPoint);
    return concatBytes(outPoint.txHash, uint32Le(outPoint.index));
}

/**
 * Serializes a molecule `CellInput` struct.
 * @param since The input's since bound.
 * @param previousOutput The consumed cell's out point.
 * @returns The 44 bytes.
 */
export function moleculeCellInput(since: bigint, previousOutput: OutPoint): Uint8Array {
    return concatBytes(uint64Le(since), moleculeOutPoint(previousOutput));
}

/**
 * Serializes a molecule `CellOutput` table.
 * @param capacity Capacity in shannons.
 * @param lock Lock script of the cell.
 * @param type Type script of the cell, or `null` for none.
 * @returns The CellOutput bytes.
 */
export function moleculeCellOutput(capacity: bigint, lock: Script, type: Script | null): Uint8Array {
    return moleculeTable([uint64Le(capacity), moleculeScript(lock), moleculeScriptOpt(type)]);
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
export function moleculeRawTransaction(fields: RawTransactionFields): Uint8Array {
    for (const [index, cellDep] of fields.cellDeps.entries()) assertBytes(`cellDeps[${index}]`, cellDep, CELL_DEP_LENGTH);
    for (const [index, headerDep] of fields.headerDeps.entries()) assertBytes(`headerDeps[${index}]`, headerDep, HASH256_LENGTH);
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
export function moleculeTransaction(raw: Uint8Array, witnesses: Uint8Array[]): Uint8Array {
    return moleculeTable([raw, moleculeDynvec(witnesses.map(moleculeBytes))]);
}
