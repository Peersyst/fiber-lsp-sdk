import { bytesToHex } from "@noble/hashes/utils.js";
import { encodeWellFormedUtf8 } from "../../../../src/common/utils/utf8.utils";

describe("encodeWellFormedUtf8", () => {
    it.each([
        ["nothing", "", ""],
        ["ascii", "coffee", "636f66666565"],
        ["U+0080, the first two-byte point", "\u0080", "c280"],
        ["U+07FF, the last two-byte point", "߿", "dfbf"],
        ["U+0800, the first three-byte point", "ࠀ", "e0a080"],
        ["U+D7FF, the last point before the surrogates", "\ud7ff", "ed9fbf"],
        ["U+E000, the first point after the surrogates", "\ue000", "ee8080"],
        ["U+FFFF, the last three-byte point", "￿", "efbfbf"],
        ["U+10000, the first four-byte point", "\u{10000}", "f0908080"],
        ["U+10FFFF, the last point", "\u{10ffff}", "f48fbfbf"],
        ["a surrogate pair, as the one point it encodes", "😀", "f09f9880"],
    ])("writes %s", (_, text, hex) => {
        expect(bytesToHex(encodeWellFormedUtf8("text", text))).toBe(hex);
    });

    it.each([
        ["a lone high surrogate", "a\ud83d"],
        ["a lone low surrogate", "\ude00b"],
        ["a low surrogate before its high one", "\ude00\ud83d"],
        ["U+D800, the first surrogate, alone", "\ud800"],
        ["U+DFFF, the last surrogate, alone", "\udfff"],
    ])("refuses %s, which the platform encoders replace in silence", (_, text) => {
        expect(() => encodeWellFormedUtf8("description", text)).toThrow(new TypeError("description must be well-formed Unicode"));
    });

    it("refuses a value that is not a string", () => {
        expect(() => encodeWellFormedUtf8("description", ["coffee"] as never)).toThrow(new TypeError("description must be a string"));
    });
});
