import { MAX_AMOUNT_SHANNONS, assertDecimalShannons } from "../../common";
import type { Field, UintHexWire } from "../../wire";
import { decodeUintHex, encodeUintHex } from "../../wire";

/**
 * Writes decimal shannons as fiber's `U128Hex`.
 * @param name Name of the amount, used in the error message.
 * @param shannons Amount in decimal shannons.
 * @returns The hex amount.
 */
export function encodeShannons(name: string, shannons: string): UintHexWire {
    assertDecimalShannons(name, shannons);
    return encodeUintHex(BigInt(shannons), MAX_AMOUNT_SHANNONS);
}

/**
 * Reads fiber's `U128Hex` as decimal shannons.
 * @param field Field to read.
 * @returns The amount in decimal shannons.
 */
export function decodeShannons(field: Field): string {
    return decodeUintHex(field, MAX_AMOUNT_SHANNONS).toString();
}
