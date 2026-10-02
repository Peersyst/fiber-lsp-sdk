import { assertString } from "../../common";
import { refuseInvoice } from "../invoice.error";

/**
 * Writes text as UTF-8, refusing a lone surrogate, which the platform encoders replace in silence.
 * @param name Name of the value, used in the error message.
 * @param text Text to write.
 * @returns The bytes.
 */
export function encodeInvoiceUtf8(name: string, text: string): Uint8Array {
    assertString(name, text);
    const bytes: number[] = [];
    for (const character of text) {
        const point = character.codePointAt(0) ?? 0;
        if (point >= 0xd800 && point <= 0xdfff) throw new TypeError(`${name} must be well-formed Unicode`);
        if (point < 0x80) bytes.push(point);
        else if (point < 0x800) bytes.push(0xc0 | (point >>> 6), 0x80 | (point & 0x3f));
        else if (point < 0x10000) bytes.push(0xe0 | (point >>> 12), 0x80 | ((point >>> 6) & 0x3f), 0x80 | (point & 0x3f));
        else bytes.push(0xf0 | (point >>> 18), 0x80 | ((point >>> 12) & 0x3f), 0x80 | ((point >>> 6) & 0x3f), 0x80 | (point & 0x3f));
    }
    return Uint8Array.from(bytes);
}

/**
 * Reads the six payload bits of a continuation byte.
 * @param byte The byte, `undefined` past the end.
 * @param path What is being read, named in a refusal.
 * @returns The payload bits.
 */
function continuationBits(byte: number | undefined, path: string): number {
    if (byte === undefined || (byte & 0xc0) !== 0x80) refuseInvoice(path, "must be UTF-8");
    return byte & 0x3f;
}

/**
 * Reads UTF-8 as Rust's `String::from_utf8` does: no overlong form, no surrogate, nothing past U+10FFFF, nothing cut.
 * @param bytes The bytes.
 * @param path What is being read, named in a refusal.
 * @returns The text.
 */
export function decodeInvoiceUtf8(bytes: Uint8Array, path: string): string {
    let text = "";
    let index = 0;
    while (index < bytes.length) {
        const lead = bytes[index] ?? 0;
        let length: number;
        let point: number;
        let minimum: number;
        if (lead < 0x80) [length, point, minimum] = [1, lead, 0];
        else if ((lead & 0xe0) === 0xc0) [length, point, minimum] = [2, lead & 0x1f, 0x80];
        else if ((lead & 0xf0) === 0xe0) [length, point, minimum] = [3, lead & 0x0f, 0x800];
        else if ((lead & 0xf8) === 0xf0) [length, point, minimum] = [4, lead & 0x07, 0x10000];
        else refuseInvoice(path, "must be UTF-8");
        for (let offset = 1; offset < length; offset++) point = (point << 6) | continuationBits(bytes[index + offset], path);
        if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) refuseInvoice(path, "must be UTF-8");
        text += String.fromCodePoint(point);
        index += length;
    }
    return text;
}
