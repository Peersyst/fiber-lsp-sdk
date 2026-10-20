import { HASH256_LENGTH, SCRIPT_HASH_TYPES, SCRIPT_HASH_TYPE_BYTES, UINT32_LENGTH } from "../common.constants";
import type { Script, ScriptHashType } from "../common.types";

const SCRIPT_FIELDS = 3;

export type MoleculeFault =
    | { kind: "size" }
    | { kind: "header" }
    | { kind: "fieldCount"; fields: number }
    | { kind: "offsets" }
    | { kind: "fixedSize"; bytes: number }
    | { kind: "bytesLength" }
    | { kind: "itemIdMissing" }
    | { kind: "itemId"; items: number }
    | { kind: "hashType" };

export type MoleculeRefuse = (path: string, fault: MoleculeFault) => never;

export type MoleculeScriptFieldNames = { codeHash: string; hashType: string; args: string };

/**
 * Words a molecule fault as a refusal reason: what the value had to be, never what it was.
 * @param fault The fault.
 * @returns The reason.
 */
export function moleculeFaultReason(fault: MoleculeFault): string {
    switch (fault.kind) {
        case "size":
            return "must be exactly as long as its size says";
        case "header":
            return "must have a whole header";
        case "fieldCount":
            return `must have exactly ${fault.fields} field${fault.fields === 1 ? "" : "s"}`;
        case "offsets":
            return "must have offsets in order";
        case "fixedSize":
            return `must be exactly ${fault.bytes} byte${fault.bytes === 1 ? "" : "s"}`;
        case "bytesLength":
            return "must be exactly as long as its length says";
        case "itemIdMissing":
            return "must start with an item id";
        case "itemId":
            return `must have an item id below ${fault.items}`;
        case "hashType":
            return `must be one of ${SCRIPT_HASH_TYPES.join(", ")}`;
    }
}

/**
 * Reads a little-endian `u32` the caller has checked is there.
 * @param bytes The bytes.
 * @param offset Where the `u32` starts.
 * @returns The value.
 */
function readUint32Le(bytes: Uint8Array, offset: number): number {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

/**
 * Checks a table's or a dynvec's size and header, as molecule's strict verifier does.
 * @param bytes The whole table or dynvec.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns How many items its header delimits.
 */
function readHeaderCount(bytes: Uint8Array, path: string, refuse: MoleculeRefuse): number {
    if (bytes.length < UINT32_LENGTH || readUint32Le(bytes, 0) !== bytes.length) refuse(path, { kind: "size" });
    if (bytes.length === UINT32_LENGTH) return 0;
    if (bytes.length < 2 * UINT32_LENGTH) refuse(path, { kind: "header" });
    const first = readUint32Le(bytes, UINT32_LENGTH);
    if (first % UINT32_LENGTH !== 0 || first < 2 * UINT32_LENGTH || first > bytes.length) refuse(path, { kind: "header" });
    return first / UINT32_LENGTH - 1;
}

/**
 * Reads the offset an item starts at, the table's size past the last one.
 * @param bytes The whole table or dynvec.
 * @param count How many items its header delimits.
 * @param index The item.
 * @returns The offset.
 */
function offsetAt(bytes: Uint8Array, count: number, index: number): number {
    return index < count ? readUint32Le(bytes, UINT32_LENGTH * (index + 1)) : bytes.length;
}

/**
 * Splits the items of a header already checked, refusing offsets out of order.
 * @param bytes The whole table or dynvec.
 * @param count How many items its header delimits.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The items.
 */
function splitAtOffsets(bytes: Uint8Array, count: number, path: string, refuse: MoleculeRefuse): Uint8Array[] {
    return Array.from({ length: count }, (_, index) => {
        const start = offsetAt(bytes, count, index);
        const end = offsetAt(bytes, count, index + 1);
        if (start > end) refuse(path, { kind: "offsets" });
        return bytes.subarray(start, end);
    });
}

/**
 * Reads a molecule table with exactly `fieldCount` fields, checked before the offsets as molecule's verifier does.
 * @param bytes The table.
 * @param fieldCount How many fields the schema declares.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The fields' bytes.
 */
export function readMoleculeTable(bytes: Uint8Array, fieldCount: number, path: string, refuse: MoleculeRefuse): Uint8Array[] {
    const count = readHeaderCount(bytes, path, refuse);
    if (count !== fieldCount) refuse(path, { kind: "fieldCount", fields: fieldCount });
    return splitAtOffsets(bytes, count, path, refuse);
}

/**
 * Reads a molecule dynvec.
 * @param bytes The dynvec.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The items' bytes.
 */
export function readMoleculeDynvec(bytes: Uint8Array, path: string, refuse: MoleculeRefuse): Uint8Array[] {
    return splitAtOffsets(bytes, readHeaderCount(bytes, path, refuse), path, refuse);
}

/**
 * Reads a molecule fixed-size value: a struct, an array, or a single byte.
 * @param bytes The value.
 * @param length Its schema size.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The bytes, checked to be that size.
 */
export function readMoleculeFixed(bytes: Uint8Array, length: number, path: string, refuse: MoleculeRefuse): Uint8Array {
    if (bytes.length !== length) refuse(path, { kind: "fixedSize", bytes: length });
    return bytes;
}

/**
 * Reads a molecule `Bytes`: a length, then exactly that many bytes.
 * @param bytes The `Bytes`.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The raw data, a view over the input.
 */
export function readMoleculeBytes(bytes: Uint8Array, path: string, refuse: MoleculeRefuse): Uint8Array {
    if (bytes.length < UINT32_LENGTH || readUint32Le(bytes, 0) !== bytes.length - UINT32_LENGTH) refuse(path, { kind: "bytesLength" });
    return bytes.subarray(UINT32_LENGTH);
}

/**
 * Reads a little-endian unsigned integer of a molecule struct.
 * @param bytes The value.
 * @param length Its width in bytes.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The value.
 */
export function readMoleculeUint(bytes: Uint8Array, length: number, path: string, refuse: MoleculeRefuse): bigint {
    return readMoleculeFixed(bytes, length, path, refuse).reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

/**
 * Reads a molecule union: the schema item its id selects, and the item's bytes.
 * @param bytes The union.
 * @param items The schema's items, in order, each at its id.
 * @param path Path named in a refusal.
 * @param refuse Ends the read with a refusal.
 * @returns The item's name and bytes.
 */
export function readMoleculeUnion<Name>(
    bytes: Uint8Array,
    items: readonly Name[],
    path: string,
    refuse: MoleculeRefuse,
): { name: Name; item: Uint8Array } {
    if (bytes.length < UINT32_LENGTH) refuse(path, { kind: "itemIdMissing" });
    const name = items[readUint32Le(bytes, 0)];
    if (name === undefined) refuse(path, { kind: "itemId", items: items.length });
    return { name, item: bytes.subarray(UINT32_LENGTH) };
}

/**
 * Reads a molecule `Script` field by field, refusing a hash type CKB does not define, which molecule itself lets through.
 * @param bytes The script.
 * @param path Path named in a refusal.
 * @param names Field names for a refusal's path.
 * @param refuse Ends the read with a refusal.
 * @returns The script, copied out of the input.
 */
export function readMoleculeScript(bytes: Uint8Array, path: string, names: MoleculeScriptFieldNames, refuse: MoleculeRefuse): Script {
    const [codeHash, hashType, args] = readMoleculeTable(bytes, SCRIPT_FIELDS, path, refuse) as [Uint8Array, Uint8Array, Uint8Array];
    readMoleculeFixed(codeHash, HASH256_LENGTH, `${path}.${names.codeHash}`, refuse);
    const byte = readMoleculeFixed(hashType, 1, `${path}.${names.hashType}`, refuse)[0];
    const name = SCRIPT_HASH_TYPES.find((candidate: ScriptHashType) => SCRIPT_HASH_TYPE_BYTES[candidate] === byte);
    if (name === undefined) refuse(`${path}.${names.hashType}`, { kind: "hashType" });
    return { codeHash: codeHash.slice(), hashType: name, args: readMoleculeBytes(args, `${path}.${names.args}`, refuse).slice() };
}
