import { refuseInvoice } from "./invoice.error";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const SEPARATOR = "1";
const CHECKSUM_GROUPS = 6;
// BIP-350's; fiber refuses plain bech32's, which is 1.
const BECH32M_CONSTANT = 0x2bc830a3;
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const UPPERCASE_PATTERN = /[A-Z]/;

export type InvoiceBech32mParts = {
    hrp: string;
    groups: number[];
};

/**
 * BIP-173's checksum polynomial over five-bit values.
 * @param values The expanded human-readable part followed by the data groups.
 * @returns The residue.
 */
function polymod(values: number[]): number {
    let checksum = 1;
    for (const value of values) {
        const top = checksum >>> 25;
        checksum = ((checksum & 0x1ffffff) << 5) ^ value;
        for (const [bit, generator] of GENERATOR.entries()) {
            if ((top >>> bit) & 1) checksum ^= generator;
        }
    }
    return checksum >>> 0;
}

/**
 * Expands the human-readable part into the values its checksum covers: the high bits of each character, a zero, the low bits.
 * @param hrp The human-readable part.
 * @returns The expanded values.
 */
function expandHrp(hrp: string): number[] {
    const codes = Array.from(hrp, (character) => character.charCodeAt(0));
    return [...codes.map((code) => code >>> 5), 0, ...codes.map((code) => code & 31)];
}

/**
 * Splits a bech32m string into its human-readable part and data groups, refusing anything fiber would not have written.
 * @param text The string.
 * @returns The human-readable part and the data groups, checksum removed.
 */
export function decodeInvoiceBech32m(text: string): InvoiceBech32mParts {
    // Fiber reads uppercase but writes lowercase: one invoice, one string.
    if (UPPERCASE_PATTERN.test(text)) refuseInvoice("invoice", "must be lowercase");
    const separator = text.lastIndexOf(SEPARATOR);
    if (separator < 1) refuseInvoice("invoice", "must have a human-readable part before the last 1");
    const hrp = text.slice(0, separator);
    const groups = Array.from(text.slice(separator + 1), (character) => CHARSET.indexOf(character));
    if (groups.includes(-1)) refuseInvoice("invoice", "must write its data in the bech32 charset");
    if (groups.length < CHECKSUM_GROUPS) refuseInvoice("invoice", "must end with a six-character checksum");
    if (polymod([...expandHrp(hrp), ...groups]) !== BECH32M_CONSTANT) refuseInvoice("invoice", "must carry a valid bech32m checksum");
    return { hrp, groups: groups.slice(0, -CHECKSUM_GROUPS) };
}

/**
 * Writes a human-readable part and data groups as a bech32m string.
 * @param hrp The human-readable part, lowercase.
 * @param groups The five-bit data groups.
 * @returns The string, checksum appended.
 */
export function encodeInvoiceBech32m(hrp: string, groups: number[]): string {
    const residue = polymod([...expandHrp(hrp), ...groups, ...new Array<number>(CHECKSUM_GROUPS).fill(0)]) ^ BECH32M_CONSTANT;
    const checksum = Array.from({ length: CHECKSUM_GROUPS }, (_, index) => (residue >>> (5 * (CHECKSUM_GROUPS - 1 - index))) & 31);
    return `${hrp}${SEPARATOR}${[...groups, ...checksum].map((group) => CHARSET.charAt(group)).join("")}`;
}

/**
 * Regroups bytes into five-bit groups, most significant bit first, zero padding the last one.
 * @param bytes The bytes.
 * @returns The groups.
 */
export function bytesToInvoiceGroups(bytes: Uint8Array): number[] {
    const groups: number[] = [];
    let accumulator = 0;
    let bits = 0;
    for (const byte of bytes) {
        accumulator = ((accumulator << 8) | byte) & 0xfff;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            groups.push((accumulator >>> bits) & 31);
        }
    }
    if (bits > 0) groups.push((accumulator << (5 - bits)) & 31);
    return groups;
}

/**
 * Regroups five-bit groups into bytes, refusing padding that is a whole group or not zero, so one byte string has one form.
 * @param groups The groups.
 * @param path What is being read, named in a refusal.
 * @returns The bytes.
 */
export function invoiceGroupsToBytes(groups: number[], path: string): Uint8Array {
    const bytes: number[] = [];
    let accumulator = 0;
    let bits = 0;
    for (const group of groups) {
        accumulator = ((accumulator << 5) | group) & 0xfff;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((accumulator >>> bits) & 0xff);
        }
    }
    if (bits >= 5 || (accumulator & ((1 << bits) - 1)) !== 0) refuseInvoice(path, "must be whole bytes with zero padding");
    return Uint8Array.from(bytes);
}
