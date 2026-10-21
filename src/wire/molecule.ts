import type { CellOutput, MoleculeFault } from "../common";
import { moleculeFaultReason, readMoleculeScript, readMoleculeTable, readMoleculeUint, UINT64_LENGTH } from "../common";
import { decodeAnyHexBytes } from "./hex";
import { WireError } from "./wire.error";
import type { WireField } from "./wire.types";

const CELL_OUTPUT_FIELDS = 3;

const SCRIPT_FIELD_NAMES = { codeHash: "code_hash", hashType: "hash_type", args: "args" };

/**
 * Refuses a field's molecule bytes as a wire error.
 * @param path Path of the broken part.
 * @param fault What the read found broken.
 */
function refuseMolecule(path: string, fault: MoleculeFault): never {
    throw new WireError(path, moleculeFaultReason(fault));
}

/**
 * Reads a field as the molecule bytes of a CKB `CellOutput`, the form fiber's `EntityHex` writes one in.
 * @param field Field to read.
 * @returns The cell output.
 */
export function decodeMoleculeCellOutput(field: WireField): CellOutput {
    const [capacity, lock, type] = readMoleculeTable(decodeAnyHexBytes(field), CELL_OUTPUT_FIELDS, field.path, refuseMolecule) as [
        Uint8Array,
        Uint8Array,
        Uint8Array,
    ];
    return {
        capacityShannons: readMoleculeUint(capacity, UINT64_LENGTH, `${field.path}.capacity`, refuseMolecule),
        lock: readMoleculeScript(lock, `${field.path}.lock`, SCRIPT_FIELD_NAMES, refuseMolecule),
        type: type.length === 0 ? null : readMoleculeScript(type, `${field.path}.type`, SCRIPT_FIELD_NAMES, refuseMolecule),
    };
}
