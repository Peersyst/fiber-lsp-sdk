import type { CellDep, CellOutput, Transaction } from "../common";
import {
    DEP_TYPES,
    HASH256_LENGTH,
    UINT32_MAX,
    UINT64_MAX,
    assertAnyBytes,
    assertBytes,
    assertOneOf,
    assertOutPoint,
    assertScript,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    ckbBlake2b,
    isPlainObject,
} from "../common";
import { MAX_CAPACITY_SHANNONS } from "./digest.constants";
import { moleculeCellDep, moleculeCellInput, moleculeCellOutput, moleculeRawTransaction } from "./utils";

/**
 * Port of fiber's `compute_tx_message`: the CKB blake2b of the raw tx with its cell deps emptied.
 * @param tx The tx; its cell deps and witnesses never reach the message.
 * @returns The 32-byte message.
 */
export function computeTxMessage(tx: Transaction): Uint8Array {
    // Emptied on purpose, so a script upgrade that moves the deps never invalidates a signature.
    return ckbBlake2b(serializeRawTransaction(tx, false));
}

/**
 * Serializes a tx's molecule `RawTransaction` after checking it field by field.
 * @param tx The tx.
 * @param withCellDeps Whether to write the tx's cell deps or none.
 * @returns The RawTransaction bytes.
 */
export function serializeRawTransaction(tx: Transaction, withCellDeps: boolean): Uint8Array {
    if (!isPlainObject(tx)) throw new TypeError("transaction must be an object");
    const { version, cellDeps, headerDeps, inputs, outputs, outputsData } = tx;
    assertUnsignedInteger("transaction.version", version, UINT32_MAX);
    const lists = { headerDeps, inputs, outputs, outputsData };
    for (const [name, list] of Object.entries(withCellDeps ? { cellDeps, ...lists } : lists)) {
        if (!Array.isArray(list)) throw new TypeError(`transaction.${name} must be an array`);
    }
    return moleculeRawTransaction({
        version,
        cellDeps: withCellDeps ? cellDeps.map((cellDep, index) => serializeCellDep(`transaction.cellDeps[${index}]`, cellDep)) : [],
        headerDeps: headerDeps.map((headerDep, index) => {
            assertBytes(`transaction.headerDeps[${index}]`, headerDep, HASH256_LENGTH);
            return headerDep;
        }),
        inputs: inputs.map((input, index) => {
            const name = `transaction.inputs[${index}]`;
            if (!isPlainObject(input)) throw new TypeError(`${name} must be an object`);
            assertUnsignedBigInt(`${name}.since`, input.since, UINT64_MAX);
            assertOutPoint(`${name}.previousOutput`, input.previousOutput);
            return moleculeCellInput(input.since, input.previousOutput);
        }),
        outputs: outputs.map((output, index) => serializeOutput(`transaction.outputs[${index}]`, output)),
        outputsData: outputsData.map((data, index) => {
            assertAnyBytes(`transaction.outputsData[${index}]`, data);
            return data;
        }),
    });
}

/**
 * The message of fiber's `Musig2SignableContent::Revocation`: the CKB blake2b of the output, its data and the args.
 * @param output The punishment output.
 * @param outputData The molecule `Bytes`, length header included.
 * @param args The revoked commitment cell's lock args.
 * @returns The 32-byte message.
 */
export function computeRevocationContentMessage(output: CellOutput, outputData: Uint8Array, args: Uint8Array): Uint8Array {
    const serializedOutput = serializeOutput("output", output);
    assertAnyBytes("outputData", outputData);
    assertAnyBytes("args", args);
    return ckbBlake2b(serializedOutput, outputData, args);
}

/**
 * Serializes a cell dep after checking it field by field.
 * @param name Its path, for the refusal.
 * @param cellDep The cell dep.
 * @returns The molecule `CellDep` bytes.
 */
function serializeCellDep(name: string, cellDep: CellDep): Uint8Array {
    if (!isPlainObject(cellDep)) throw new TypeError(`${name} must be an object`);
    assertOutPoint(`${name}.outPoint`, cellDep.outPoint);
    assertOneOf(`${name}.depType`, cellDep.depType, DEP_TYPES);
    return moleculeCellDep(cellDep);
}

/**
 * Serializes a cell output after checking it field by field.
 * @param name Its path, for the refusal.
 * @param output The output.
 * @returns The molecule `CellOutput` bytes.
 */
function serializeOutput(name: string, output: CellOutput): Uint8Array {
    if (!isPlainObject(output)) throw new TypeError(`${name} must be an object`);
    assertUnsignedBigInt(`${name}.capacityShannons`, output.capacityShannons, MAX_CAPACITY_SHANNONS);
    assertScript(`${name}.lock`, output.lock);
    if (output.type !== null) assertScript(`${name}.type`, output.type);
    return moleculeCellOutput(output.capacityShannons, output.lock, output.type);
}
