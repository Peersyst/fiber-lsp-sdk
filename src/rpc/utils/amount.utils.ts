import { MAX_AMOUNT_SHANNONS, assertDecimalShannons } from "../../common";
import type { UintHexWire, WireField } from "../../wire";
import { decodeUintHex, encodeUintHex } from "../../wire";

/**
 * Writes decimal shannons as fiber's `U128Hex`.
 * @param name Name of the amount, used in the error message.
 * @param shannons Amount in decimal shannons.
 * @returns The hex amount.
 */
export function encodeRpcShannons(name: string, shannons: string): UintHexWire {
    assertDecimalShannons(name, shannons);
    return encodeUintHex(name, BigInt(shannons), MAX_AMOUNT_SHANNONS);
}

/**
 * Reads fiber's `U128Hex` as decimal shannons.
 * @param field Field to read.
 * @returns The amount in decimal shannons.
 */
export function decodeRpcShannons(field: WireField): string {
    return decodeUintHex(field, MAX_AMOUNT_SHANNONS).toString();
}
