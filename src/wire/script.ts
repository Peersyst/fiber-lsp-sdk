import type { OutPoint, Script } from "../common";
import { HASH256_LENGTH, SCRIPT_HASH_TYPES, UINT32_MAX } from "../common";
import { decodeEnum, readObject } from "./field";
import { decodeAnyHexBytes, decodeHexBytes } from "./hex";
import { decodeUintHexNumber } from "./uint";
import type { Field, OutPointWire, ScriptWire } from "./wire.types";

/**
 * Reads a field as a script in CKB's JSON shape.
 * @param field Field to read.
 * @returns The script.
 */
export function decodeScript(field: Field): Script {
    const at = readObject<ScriptWire>(field);
    return {
        codeHash: decodeHexBytes(at("code_hash"), HASH256_LENGTH),
        hashType: decodeEnum(at("hash_type"), SCRIPT_HASH_TYPES),
        args: decodeAnyHexBytes(at("args")),
    };
}

/**
 * Reads a field as a script or an explicit `null`; an absent field is not an absent script.
 * @param field Field to read.
 * @returns The script, or `null`.
 */
export function decodeScriptOrNull(field: Field): Script | null {
    return field.value === null ? null : decodeScript(field);
}

/**
 * Reads a field as an outpoint in CKB's JSON shape.
 * @param field Field to read.
 * @returns The outpoint.
 */
export function decodeOutPoint(field: Field): OutPoint {
    const at = readObject<OutPointWire>(field);
    return { txHash: decodeHexBytes(at("tx_hash"), HASH256_LENGTH), index: decodeUintHexNumber(at("index"), UINT32_MAX) };
}
