import { AgentRequestError } from "./agent.error";
import { BYTES32_HEX_PATTERN, HEX_BYTES_PATTERN, UINT32_MAX } from "./agent.constants";
import { readExactJsonObject } from "./agent.utils";

export type CkbOutPointJson = { tx_hash: string; index: string };

export type CkbCellDepJson = { out_point: CkbOutPointJson; dep_type: "code" | "dep_group" };

// CKB's JSON writes integers as lowercase hex with no leading zero.
const CKB_QUANTITY_PATTERN = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;

/**
 * Reads one of CKB's hex integers, within a bound.
 * @param value The value.
 * @param max The largest it may be.
 * @param field Where it sits.
 * @returns The hex, as sent.
 */
export function readCkbQuantity(value: unknown, max: bigint, field: string): string {
    if (typeof value !== "string" || !CKB_QUANTITY_PATTERN.test(value)) throw new AgentRequestError(`${field} must be a hex integer`);
    if (BigInt(value) > max) throw new AgentRequestError(`${field} is out of range`);
    return value;
}

/**
 * Reads 0x hex bytes.
 * @param value The value.
 * @param field Where it sits.
 * @returns The hex, as sent.
 */
export function readCkbBytes(value: unknown, field: string): string {
    if (typeof value !== "string" || !HEX_BYTES_PATTERN.test(value)) throw new AgentRequestError(`${field} must be 0x hex bytes`);
    return value;
}

/**
 * Reads a 32-byte hash.
 * @param value The value.
 * @param field Where it sits.
 * @returns The hash, as sent.
 */
export function readCkbHash(value: unknown, field: string): string {
    if (typeof value !== "string" || !BYTES32_HEX_PATTERN.test(value)) throw new AgentRequestError(`${field} must be 32 bytes of 0x hex`);
    return value;
}

/**
 * Reads an out point.
 * @param value The value.
 * @param field Where it sits.
 * @returns The out point.
 */
export function readCkbOutPoint(value: unknown, field: string): CkbOutPointJson {
    const outPoint = readExactJsonObject(value, ["tx_hash", "index"], field);
    return {
        tx_hash: readCkbHash(outPoint.tx_hash, `${field}.tx_hash`),
        index: readCkbQuantity(outPoint.index, UINT32_MAX, `${field}.index`),
    };
}

/**
 * Reads a cell dep.
 * @param value The value.
 * @param field Where it sits.
 * @returns The cell dep.
 */
export function readCkbCellDep(value: unknown, field: string): CkbCellDepJson {
    const dep = readExactJsonObject(value, ["out_point", "dep_type"], field);
    const depType = dep.dep_type;
    if (depType !== "code" && depType !== "dep_group") throw new AgentRequestError(`${field}.dep_type must be code or dep_group`);
    return { out_point: readCkbOutPoint(dep.out_point, `${field}.out_point`), dep_type: depType };
}
