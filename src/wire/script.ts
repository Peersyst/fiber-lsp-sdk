import type { OutPoint, Script } from "../common";
import { HASH256_LENGTH, SCRIPT_HASH_TYPES, UINT32_MAX, assertOneOf } from "../common";
import { decodeEnum, decodeOrNull, readObject } from "./field";
import { decodeAnyHexBytes, decodeHexBytes, encodeAnyHexBytes, encodeHexBytes } from "./hex";
import { decodeUintHexNumber, encodeUintHexNumber } from "./uint";
import type { OutPointWire, ScriptWire, WireField } from "./wire.types";

/**
 * Reads a field as a script in CKB's JSON shape.
 * @param field Field to read.
 * @returns The script.
 */
export function decodeScript(field: WireField): Script {
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
export function decodeScriptOrNull(field: WireField): Script | null {
    return decodeOrNull(field, decodeScript);
}

/**
 * Reads a field as an outpoint in CKB's JSON shape.
 * @param field Field to read.
 * @returns The outpoint.
 */
export function decodeOutPoint(field: WireField): OutPoint {
    const at = readObject<OutPointWire>(field);
    return { txHash: decodeHexBytes(at("tx_hash"), HASH256_LENGTH), index: decodeUintHexNumber(at("index"), UINT32_MAX) };
}

/**
 * Writes a script in CKB's JSON shape.
 * @param name Name of the script, used in the error messages.
 * @param script Script to write.
 * @returns The wire script.
 */
export function encodeScript(name: string, script: Script): ScriptWire {
    assertOneOf(`${name}.hashType`, script.hashType, SCRIPT_HASH_TYPES);
    return {
        code_hash: encodeHexBytes(`${name}.codeHash`, script.codeHash, HASH256_LENGTH),
        hash_type: script.hashType,
        args: encodeAnyHexBytes(`${name}.args`, script.args),
    };
}

/**
 * Writes a script in CKB's JSON shape, or `null` for no script.
 * @param name Name of the script, used in the error messages.
 * @param script Script to write, or `null`.
 * @returns The wire script, or `null`.
 */
export function encodeScriptOrNull(name: string, script: Script | null): ScriptWire | null {
    return script === null ? null : encodeScript(name, script);
}

/**
 * Writes an outpoint in CKB's JSON shape.
 * @param name Name of the outpoint, used in the error messages.
 * @param outPoint Outpoint to write.
 * @returns The wire outpoint.
 */
export function encodeOutPoint(name: string, outPoint: OutPoint): OutPointWire {
    return {
        tx_hash: encodeHexBytes(`${name}.txHash`, outPoint.txHash, HASH256_LENGTH),
        index: encodeUintHexNumber(`${name}.index`, outPoint.index, UINT32_MAX),
    };
}
