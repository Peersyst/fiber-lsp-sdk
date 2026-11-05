import { concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import type { ScriptHashType } from "@peersyst/fiber-lsp-sdk";
import { AgentRequestError } from "./agent.error";
import type { ScriptJson } from "./agent.types";
import { SCRIPT_HASH_TYPES, UINT32_MAX, UINT64_MAX } from "./agent.constants";
import { ckbBlake2b } from "./ckb-hash";
import { readExactJsonObject, readJsonList } from "./agent.utils";
import { readCkbBytes, readCkbCellDep, readCkbHash, readCkbOutPoint, readCkbQuantity } from "./ckb-json";
import type { CkbCellDepJson, CkbOutPointJson } from "./ckb-json";
import { readScriptJson } from "./open-params";

export type CkbCellInputJson = { previous_output: CkbOutPointJson; since: string };

export type CkbCellOutputJson = { capacity: string; lock: ScriptJson; type: ScriptJson | null };

export type CkbTxJson = {
    version: string;
    cell_deps: CkbCellDepJson[];
    header_deps: string[];
    inputs: CkbCellInputJson[];
    outputs: CkbCellOutputJson[];
    outputs_data: string[];
    witnesses: string[];
};

export type CkbWitnessArgs = { lock: Uint8Array | null; inputType: Uint8Array | null; outputType: Uint8Array | null };

const MOLECULE_HEADER_BYTES = 4;

const WITNESS_ARGS_FIELDS = 3;

const HASH_TYPE_BYTES: Record<ScriptHashType, number> = { data: 0, type: 1, data1: 2, data2: 4 };

const DEP_TYPE_BYTES: Record<CkbCellDepJson["dep_type"], number> = { code: 0, dep_group: 1 };

const TX_KEYS = ["version", "cell_deps", "header_deps", "inputs", "outputs", "outputs_data", "witnesses"];

/**
 * Reads a cell input.
 * @param value The value.
 * @param field Where it sits.
 * @returns The cell input.
 */
function readCellInput(value: unknown, field: string): CkbCellInputJson {
    const input = readExactJsonObject(value, ["previous_output", "since"], field);
    return {
        previous_output: readCkbOutPoint(input.previous_output, `${field}.previous_output`),
        since: readCkbQuantity(input.since, UINT64_MAX, `${field}.since`),
    };
}

/**
 * Reads a cell output.
 * @param value The value.
 * @param field Where it sits.
 * @returns The cell output.
 */
function readCellOutput(value: unknown, field: string): CkbCellOutputJson {
    const output = readExactJsonObject(value, ["capacity", "lock", "type"], field);
    return {
        capacity: readCkbQuantity(output.capacity, UINT64_MAX, `${field}.capacity`),
        lock: readScriptJson(output.lock, `${field}.lock`),
        type: output.type === null || output.type === undefined ? null : readScriptJson(output.type, `${field}.type`),
    };
}

/**
 * Reads a transaction in CKB's JSON, refusing any field it does not have.
 * @param value The value.
 * @param field Where it sits.
 * @returns The transaction, as sent.
 */
export function readCkbTxJson(value: unknown, field: string): CkbTxJson {
    const tx = readExactJsonObject(value, TX_KEYS, field);
    const read: CkbTxJson = {
        version: readCkbQuantity(tx.version, UINT32_MAX, `${field}.version`),
        cell_deps: readJsonList(tx.cell_deps, `${field}.cell_deps`, readCkbCellDep),
        header_deps: readJsonList(tx.header_deps, `${field}.header_deps`, readCkbHash),
        inputs: readJsonList(tx.inputs, `${field}.inputs`, readCellInput),
        outputs: readJsonList(tx.outputs, `${field}.outputs`, readCellOutput),
        outputs_data: readJsonList(tx.outputs_data, `${field}.outputs_data`, readCkbBytes),
        witnesses: readJsonList(tx.witnesses, `${field}.witnesses`, readCkbBytes),
    };
    if (read.outputs_data.length !== read.outputs.length)
        throw new AgentRequestError(`${field} has ${read.outputs.length} outputs but ${read.outputs_data.length} outputs_data`);
    return read;
}

/**
 * Writes an integer as little-endian bytes.
 * @param value The integer.
 * @param bytes How many bytes.
 * @returns The bytes.
 */
function littleEndian(value: bigint, bytes: number): Uint8Array {
    const out = new Uint8Array(bytes);
    for (let index = 0; index < bytes; index += 1) out[index] = Number((value >> BigInt(8 * index)) & 0xffn);
    return out;
}

/**
 * Writes a molecule `Uint64`.
 * @param value The integer.
 * @returns Its 8 bytes.
 */
export function moleculeUint64(value: number | bigint): Uint8Array {
    return littleEndian(BigInt(value), 8);
}

/**
 * Writes a molecule `Uint32`.
 * @param value The integer.
 * @returns Its 4 bytes.
 */
function uint32(value: number | bigint): Uint8Array {
    return littleEndian(BigInt(value), 4);
}

/**
 * Writes a molecule `Bytes`: its length, then the bytes.
 * @param data The bytes.
 * @returns The fixvec.
 */
export function moleculeBytes(data: Uint8Array): Uint8Array {
    return concatBytes(uint32(data.length), data);
}

/**
 * Writes a molecule fixvec of items already serialized.
 * @param items The items.
 * @returns The fixvec.
 */
function fixvec(items: readonly Uint8Array[]): Uint8Array {
    return concatBytes(uint32(items.length), ...items);
}

/**
 * Writes a molecule table or dynvec: its size, each field's offset, then the fields.
 * @param fields The fields, already serialized.
 * @returns The table.
 */
function table(fields: readonly Uint8Array[]): Uint8Array {
    const headerBytes = MOLECULE_HEADER_BYTES * (fields.length + 1);
    const offsets: Uint8Array[] = [];
    let offset = headerBytes;
    for (const field of fields) {
        offsets.push(uint32(offset));
        offset += field.length;
    }
    return concatBytes(uint32(offset), ...offsets, ...fields);
}

/**
 * Writes a script.
 * @param script The script.
 * @returns The molecule `Script`.
 */
function moleculeScript(script: ScriptJson): Uint8Array {
    const hashType = SCRIPT_HASH_TYPES.find((known) => known === script.hash_type);
    if (hashType === undefined) throw new AgentRequestError(`hash_type ${script.hash_type} is not one CKB has`);
    return table([
        hexToBytes(script.code_hash.slice(2)),
        new Uint8Array([HASH_TYPE_BYTES[hashType]]),
        moleculeBytes(hexToBytes(script.args.slice(2))),
    ]);
}

/**
 * Writes an out point.
 * @param outPoint The out point.
 * @returns The molecule `OutPoint`.
 */
function moleculeOutPoint(outPoint: CkbOutPointJson): Uint8Array {
    return concatBytes(hexToBytes(outPoint.tx_hash.slice(2)), uint32(BigInt(outPoint.index)));
}

/**
 * Writes a transaction without its witnesses, as its hash covers it.
 * @param tx The transaction.
 * @returns The molecule `RawTransaction`.
 */
function moleculeRawTransaction(tx: CkbTxJson): Uint8Array {
    return table([
        uint32(BigInt(tx.version)),
        fixvec(tx.cell_deps.map((dep) => concatBytes(moleculeOutPoint(dep.out_point), new Uint8Array([DEP_TYPE_BYTES[dep.dep_type]])))),
        fixvec(tx.header_deps.map((hash) => hexToBytes(hash.slice(2)))),
        fixvec(tx.inputs.map((input) => concatBytes(moleculeUint64(BigInt(input.since)), moleculeOutPoint(input.previous_output)))),
        table(
            tx.outputs.map((output) =>
                table([
                    moleculeUint64(BigInt(output.capacity)),
                    moleculeScript(output.lock),
                    output.type === null ? new Uint8Array() : moleculeScript(output.type),
                ]),
            ),
        ),
        table(tx.outputs_data.map((data) => moleculeBytes(hexToBytes(data.slice(2))))),
    ]);
}

/**
 * Hashes a transaction as CKB does: the CKB blake2b of its raw part.
 * @param tx The transaction.
 * @returns The 32-byte tx hash.
 */
export function ckbTxHash(tx: CkbTxJson): Uint8Array {
    return ckbBlake2b(moleculeRawTransaction(tx));
}

/**
 * Writes a molecule `BytesOpt`, absent as no bytes at all.
 * @param data The bytes, or null.
 * @returns The option.
 */
function bytesOption(data: Uint8Array | null): Uint8Array {
    return data === null ? new Uint8Array() : moleculeBytes(data);
}

/**
 * Writes a `WitnessArgs`, an absent field as molecule's empty option.
 * @param witness The witness.
 * @returns The molecule `WitnessArgs`.
 */
export function moleculeWitnessArgs(witness: CkbWitnessArgs): Uint8Array {
    return table([bytesOption(witness.lock), bytesOption(witness.inputType), bytesOption(witness.outputType)]);
}

/**
 * Reads a little-endian `Uint32` out of bytes.
 * @param bytes The bytes.
 * @param at Where it starts.
 * @returns The integer.
 */
function readUint32(bytes: Uint8Array, at: number): number {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(at, true);
}

/**
 * Reads a `WitnessArgs`, refusing anything but its three fields, each empty or a whole `Bytes`.
 * @param bytes The witness.
 * @param field Where it sits.
 * @returns The witness's fields.
 */
export function readWitnessArgs(bytes: Uint8Array, field: string): CkbWitnessArgs {
    const headerBytes = MOLECULE_HEADER_BYTES * (WITNESS_ARGS_FIELDS + 1);
    if (bytes.length < headerBytes || readUint32(bytes, 0) !== bytes.length || readUint32(bytes, 4) !== headerBytes) {
        throw new AgentRequestError(`${field} is not a WitnessArgs`);
    }
    const ends = [readUint32(bytes, 8), readUint32(bytes, 12), bytes.length];
    let start = headerBytes;
    const fields = ends.map((end) => {
        if (end < start || end > bytes.length) throw new AgentRequestError(`${field} is not a WitnessArgs`);
        const data = bytes.subarray(start, end);
        start = end;
        if (data.length === 0) return null;
        if (data.length < MOLECULE_HEADER_BYTES || readUint32(data, 0) !== data.length - MOLECULE_HEADER_BYTES) {
            throw new AgentRequestError(`${field} is not a WitnessArgs`);
        }
        return data.slice(MOLECULE_HEADER_BYTES);
    });
    const [lock = null, inputType = null, outputType = null] = fields;
    return { lock, inputType, outputType };
}
