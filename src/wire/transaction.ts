import type { CellDep, CellInput, CellOutput, Transaction } from "../common";
import { DEP_TYPES, HASH256_LENGTH, UINT32_MAX, UINT64_MAX, assertOneOf } from "../common";
import { decodeEnum, readArray, readObject } from "./field";
import { decodeAnyHexBytes, decodeHexBytes, encodeAnyHexBytes, encodeHexBytes } from "./hex";
import { decodeOutPoint, decodeScript, decodeScriptOrNull, encodeOutPoint, encodeScript, encodeScriptOrNull } from "./script";
import { decodeUintHex, decodeUintHexNumber, encodeUintHex, encodeUintHexNumber } from "./uint";
import type { CellDepWire, CellInputWire, CellOutputWire, TransactionWire, WireField } from "./wire.types";

/**
 * Reads a field as a transaction in CKB's JSON shape.
 * @param field Field to read.
 * @returns The transaction.
 */
export function decodeTransaction(field: WireField): Transaction {
    const at = readObject<TransactionWire>(field);
    return {
        version: decodeUintHexNumber(at("version"), UINT32_MAX),
        cellDeps: readArray(at("cell_deps")).map(decodeCellDep),
        headerDeps: readArray(at("header_deps")).map((dep) => decodeHexBytes(dep, HASH256_LENGTH)),
        inputs: readArray(at("inputs")).map(decodeCellInput),
        outputs: readArray(at("outputs")).map(decodeCellOutput),
        outputsData: readArray(at("outputs_data")).map(decodeAnyHexBytes),
        witnesses: readArray(at("witnesses")).map(decodeAnyHexBytes),
    };
}

/**
 * Writes a transaction in CKB's JSON shape.
 * @param name Name of the transaction, used in the error messages.
 * @param tx Transaction to write.
 * @returns The wire transaction.
 */
export function encodeTransaction(name: string, tx: Transaction): TransactionWire {
    return {
        version: encodeUintHexNumber(`${name}.version`, tx.version, UINT32_MAX),
        cell_deps: tx.cellDeps.map((dep, index) => encodeCellDep(`${name}.cellDeps[${index}]`, dep)),
        header_deps: tx.headerDeps.map((dep, index) => encodeHexBytes(`${name}.headerDeps[${index}]`, dep, HASH256_LENGTH)),
        inputs: tx.inputs.map((input, index) => encodeCellInput(`${name}.inputs[${index}]`, input)),
        outputs: tx.outputs.map((output, index) => encodeCellOutput(`${name}.outputs[${index}]`, output)),
        outputs_data: tx.outputsData.map((data, index) => encodeAnyHexBytes(`${name}.outputsData[${index}]`, data)),
        witnesses: tx.witnesses.map((witness, index) => encodeAnyHexBytes(`${name}.witnesses[${index}]`, witness)),
    };
}

/**
 * Reads a field as a cell dep.
 * @param field Field to read.
 * @returns The cell dep.
 */
function decodeCellDep(field: WireField): CellDep {
    const at = readObject<CellDepWire>(field);
    return { outPoint: decodeOutPoint(at("out_point")), depType: decodeEnum(at("dep_type"), DEP_TYPES) };
}

/**
 * Reads a field as a cell input.
 * @param field Field to read.
 * @returns The cell input.
 */
function decodeCellInput(field: WireField): CellInput {
    const at = readObject<CellInputWire>(field);
    return { since: decodeUintHex(at("since"), UINT64_MAX), previousOutput: decodeOutPoint(at("previous_output")) };
}

/**
 * Reads a field as a cell output.
 * @param field Field to read.
 * @returns The cell output.
 */
function decodeCellOutput(field: WireField): CellOutput {
    const at = readObject<CellOutputWire>(field);
    return {
        capacityShannons: decodeUintHex(at("capacity"), UINT64_MAX),
        lock: decodeScript(at("lock")),
        type: decodeScriptOrNull(at("type")),
    };
}

/**
 * Writes a cell dep.
 * @param name Name of the cell dep, used in the error messages.
 * @param dep Cell dep to write.
 * @returns The wire cell dep.
 */
function encodeCellDep(name: string, dep: CellDep): CellDepWire {
    assertOneOf(`${name}.depType`, dep.depType, DEP_TYPES);
    return { out_point: encodeOutPoint(`${name}.outPoint`, dep.outPoint), dep_type: dep.depType };
}

/**
 * Writes a cell input.
 * @param name Name of the cell input, used in the error messages.
 * @param input Cell input to write.
 * @returns The wire cell input.
 */
function encodeCellInput(name: string, input: CellInput): CellInputWire {
    return {
        since: encodeUintHex(`${name}.since`, input.since, UINT64_MAX),
        previous_output: encodeOutPoint(`${name}.previousOutput`, input.previousOutput),
    };
}

/**
 * Writes a cell output.
 * @param name Name of the cell output, used in the error messages.
 * @param output Cell output to write.
 * @returns The wire cell output.
 */
function encodeCellOutput(name: string, output: CellOutput): CellOutputWire {
    return {
        capacity: encodeUintHex(`${name}.capacityShannons`, output.capacityShannons, UINT64_MAX),
        lock: encodeScript(`${name}.lock`, output.lock),
        type: encodeScriptOrNull(`${name}.type`, output.type),
    };
}
