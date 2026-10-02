import type { Script, ScriptHashType } from "../../common";
import { HASH256_LENGTH, SCRIPT_HASH_TYPES, SCRIPT_HASH_TYPE_BYTES, UINT32_LENGTH } from "../../common";
import { refuseInvoice } from "../invoice.error";

const SCRIPT_FIELDS = 3;

/**
 * Reads a little-endian `u32` the caller has checked is there.
 * @param bytes The bytes.
 * @param offset Where the `u32` starts.
 * @returns The value.
 */
function readU32(bytes: Uint8Array, offset: number): number {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

/**
 * Splits a header of offsets into the items it delimits, as molecule's strict verifier does for a table and a dynvec.
 * @param bytes The whole table or dynvec.
 * @param path What is being read, named in a refusal.
 * @returns The items.
 */
function readOffsets(bytes: Uint8Array, path: string): Uint8Array[] {
    if (bytes.length < UINT32_LENGTH || readU32(bytes, 0) !== bytes.length) refuseInvoice(path, "must be exactly as long as its size says");
    if (bytes.length === UINT32_LENGTH) return [];
    if (bytes.length < 2 * UINT32_LENGTH) refuseInvoice(path, "must have a whole header");
    const first = readU32(bytes, UINT32_LENGTH);
    if (first % UINT32_LENGTH !== 0 || first < 2 * UINT32_LENGTH || first > bytes.length) refuseInvoice(path, "must have a whole header");
    const count = first / UINT32_LENGTH - 1;
    const offsets = Array.from({ length: count }, (_, index) => readU32(bytes, UINT32_LENGTH * (index + 1)));
    offsets.push(bytes.length);
    return Array.from({ length: count }, (_, index) => {
        const start = offsets[index] ?? 0;
        const end = offsets[index + 1] ?? 0;
        if (start > end) refuseInvoice(path, "must have offsets in order");
        return bytes.subarray(start, end);
    });
}

/**
 * Reads a molecule table with exactly a schema's field count, as fiber's strict reader does.
 * @param bytes The table.
 * @param fieldCount How many fields the schema declares.
 * @param path What is being read, named in a refusal.
 * @returns The fields' bytes.
 */
export function readInvoiceMoleculeTable(bytes: Uint8Array, fieldCount: number, path: string): Uint8Array[] {
    const fields = readOffsets(bytes, path);
    if (fields.length !== fieldCount) refuseInvoice(path, `must have exactly ${fieldCount} field${fieldCount === 1 ? "" : "s"}`);
    return fields;
}

/**
 * Reads a molecule dynvec.
 * @param bytes The dynvec.
 * @param path What is being read, named in a refusal.
 * @returns The items' bytes.
 */
export function readInvoiceMoleculeDynvec(bytes: Uint8Array, path: string): Uint8Array[] {
    return readOffsets(bytes, path);
}

/**
 * Reads a molecule fixed-size value: a struct, an array, or a single byte.
 * @param bytes The value.
 * @param length Its schema size.
 * @param path What is being read, named in a refusal.
 * @returns The bytes, checked to be that size.
 */
export function readInvoiceMoleculeFixed(bytes: Uint8Array, length: number, path: string): Uint8Array {
    if (bytes.length !== length) refuseInvoice(path, `must be exactly ${length} byte${length === 1 ? "" : "s"}`);
    return bytes;
}

/**
 * Reads a molecule `Bytes`: a length, then exactly that many bytes.
 * @param bytes The `Bytes`.
 * @param path What is being read, named in a refusal.
 * @returns The raw data.
 */
export function readInvoiceMoleculeBytes(bytes: Uint8Array, path: string): Uint8Array {
    if (bytes.length < UINT32_LENGTH || readU32(bytes, 0) !== bytes.length - UINT32_LENGTH) {
        refuseInvoice(path, "must be exactly as long as its length says");
    }
    return bytes.subarray(UINT32_LENGTH);
}

/**
 * Reads a little-endian unsigned integer of a molecule struct.
 * @param bytes The value.
 * @param length Its width in bytes.
 * @param path What is being read, named in a refusal.
 * @returns The value.
 */
export function readInvoiceMoleculeUint(bytes: Uint8Array, length: number, path: string): bigint {
    return readInvoiceMoleculeFixed(bytes, length, path).reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

/**
 * Reads a molecule union: the schema item its id selects, and the item's bytes.
 * @param bytes The union.
 * @param items The schema's items, in order, each at its id.
 * @param path What is being read, named in a refusal.
 * @returns The item's name and bytes.
 */
export function readInvoiceMoleculeUnion<Name>(bytes: Uint8Array, items: readonly Name[], path: string): { name: Name; item: Uint8Array } {
    if (bytes.length < UINT32_LENGTH) refuseInvoice(path, "must start with an item id");
    const name = items[readU32(bytes, 0)];
    if (name === undefined) refuseInvoice(path, `must have an item id below ${items.length}`);
    return { name, item: bytes.subarray(UINT32_LENGTH) };
}

/**
 * Reads a molecule `Script`, refusing a hash type CKB does not define, which molecule itself lets through.
 * @param bytes The script.
 * @param path What is being read, named in a refusal.
 * @returns The script.
 */
export function readInvoiceMoleculeScript(bytes: Uint8Array, path: string): Script {
    const [codeHash, hashType, args] = readInvoiceMoleculeTable(bytes, SCRIPT_FIELDS, path) as [Uint8Array, Uint8Array, Uint8Array];
    const byte = readInvoiceMoleculeFixed(hashType, 1, `${path}.hashType`)[0];
    const name = SCRIPT_HASH_TYPES.find((candidate: ScriptHashType) => SCRIPT_HASH_TYPE_BYTES[candidate] === byte);
    if (name === undefined) refuseInvoice(`${path}.hashType`, `must be one of ${SCRIPT_HASH_TYPES.join(", ")}`);
    return {
        codeHash: readInvoiceMoleculeFixed(codeHash, HASH256_LENGTH, `${path}.codeHash`).slice(),
        hashType: name,
        args: readInvoiceMoleculeBytes(args, `${path}.args`).slice(),
    };
}
