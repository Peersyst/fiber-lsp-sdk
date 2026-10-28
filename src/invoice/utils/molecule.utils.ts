import type { MoleculeFault, Script } from "../../common";
import {
    SCRIPT_FIELD_NAMES,
    moleculeFaultReason,
    readMoleculeBytes,
    readMoleculeDynvec,
    readMoleculeFixed,
    readMoleculeScript,
    readMoleculeTable,
    readMoleculeUint,
    readMoleculeUnion,
} from "../../common";
import { refuseInvoice } from "../invoice.error";

/**
 * Refuses an invoice's molecule data.
 * @param path Path named in the refusal.
 * @param fault What the read found broken.
 */
function refuseMolecule(path: string, fault: MoleculeFault): never {
    refuseInvoice(path, moleculeFaultReason(fault));
}

/**
 * `readMoleculeTable`, refusing as an invoice error.
 * @param bytes The table.
 * @param fieldCount How many fields the schema declares.
 * @param path Path named in a refusal.
 * @returns The fields' bytes.
 */
export function readInvoiceMoleculeTable(bytes: Uint8Array, fieldCount: number, path: string): Uint8Array[] {
    return readMoleculeTable(bytes, fieldCount, path, refuseMolecule);
}

/**
 * `readMoleculeDynvec`, refusing as an invoice error.
 * @param bytes The dynvec.
 * @param path Path named in a refusal.
 * @returns The items' bytes.
 */
export function readInvoiceMoleculeDynvec(bytes: Uint8Array, path: string): Uint8Array[] {
    return readMoleculeDynvec(bytes, path, refuseMolecule);
}

/**
 * `readMoleculeFixed`, refusing as an invoice error.
 * @param bytes The value.
 * @param length Its schema size.
 * @param path Path named in a refusal.
 * @returns The bytes, checked to be that size.
 */
export function readInvoiceMoleculeFixed(bytes: Uint8Array, length: number, path: string): Uint8Array {
    return readMoleculeFixed(bytes, length, path, refuseMolecule);
}

/**
 * `readMoleculeBytes`, refusing as an invoice error.
 * @param bytes The `Bytes`.
 * @param path Path named in a refusal.
 * @returns The raw data.
 */
export function readInvoiceMoleculeBytes(bytes: Uint8Array, path: string): Uint8Array {
    return readMoleculeBytes(bytes, path, refuseMolecule);
}

/**
 * `readMoleculeUint`, refusing as an invoice error.
 * @param bytes The value.
 * @param length Its width in bytes.
 * @param path Path named in a refusal.
 * @returns The value.
 */
export function readInvoiceMoleculeUint(bytes: Uint8Array, length: number, path: string): bigint {
    return readMoleculeUint(bytes, length, path, refuseMolecule);
}

/**
 * `readMoleculeUnion`, refusing as an invoice error.
 * @param bytes The union.
 * @param items The schema's items, in order, each at its id.
 * @param path Path named in a refusal.
 * @returns The item's name and bytes.
 */
export function readInvoiceMoleculeUnion<Name>(bytes: Uint8Array, items: readonly Name[], path: string): { name: Name; item: Uint8Array } {
    return readMoleculeUnion(bytes, items, path, refuseMolecule);
}

/**
 * `readMoleculeScript`, refusing as an invoice error.
 * @param bytes The script.
 * @param path Path named in a refusal.
 * @returns The script.
 */
export function readInvoiceMoleculeScript(bytes: Uint8Array, path: string): Script {
    return readMoleculeScript(bytes, path, SCRIPT_FIELD_NAMES, refuseMolecule);
}
