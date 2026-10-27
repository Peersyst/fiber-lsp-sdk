import { assertString } from "./assert.utils";

/**
 * Writes text as UTF-8, refusing a lone surrogate, which the platform encoders replace in silence.
 * @param name Name for the error message.
 * @param text Text to write.
 * @returns The bytes.
 */
export function encodeWellFormedUtf8(name: string, text: string): Uint8Array {
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
