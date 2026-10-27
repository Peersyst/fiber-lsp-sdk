import { refuseInvoice } from "../invoice.error";

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
