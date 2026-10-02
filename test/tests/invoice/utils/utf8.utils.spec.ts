import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { InvoiceError } from "../../../../src/invoice";
import { decodeInvoiceUtf8, encodeInvoiceUtf8 } from "../../../../src/invoice/utils/utf8.utils";
import { invoiceRefusal } from "../../../utils/refusal";

const NOT_UTF8 = new InvoiceError("attributes[0]", "must be UTF-8");

describe("encodeInvoiceUtf8", () => {
    it.each([
        ["nothing", "", ""],
        ["ascii", "coffee", "636f66666565"],
        ["U+0080, the first two-byte point", "\u0080", "c280"],
        ["U+07FF, the last two-byte point", "߿", "dfbf"],
        ["U+0800, the first three-byte point", "ࠀ", "e0a080"],
        ["U+FFFF, the last three-byte point", "￿", "efbfbf"],
        ["U+10000, the first four-byte point", "\u{10000}", "f0908080"],
        ["U+10FFFF, the last point", "\u{10ffff}", "f48fbfbf"],
        ["a surrogate pair, as the one point it encodes", "😀", "f09f9880"],
    ])("writes %s", (_, text, hex) => {
        expect(bytesToHex(encodeInvoiceUtf8("text", text))).toBe(hex);
    });

    it.each([
        ["a lone high surrogate", "a\ud83d"],
        ["a lone low surrogate", "\ude00b"],
        ["a low surrogate before its high one", "\ude00\ud83d"],
    ])("refuses %s, which the platform encoders replace in silence", (_, text) => {
        expect(() => encodeInvoiceUtf8("description", text)).toThrow(new TypeError("description must be well-formed Unicode"));
    });

    it("refuses a value that is not a string", () => {
        expect(() => encodeInvoiceUtf8("description", ["coffee"] as never)).toThrow(new TypeError("description must be a string"));
    });
});

describe("decodeInvoiceUtf8", () => {
    it.each([
        ["nothing", "", ""],
        ["ascii with a nul byte", "610062", "a\u0000b"],
        ["every width", "61c3a9e282acf09f9880", "aé€😀"],
        ["the last point", "f48fbfbf", "\u{10ffff}"],
        ["the points around the surrogates", "ed9fbfee8080", "퟿"],
    ])("reads %s", (_, hex, text) => {
        expect(decodeInvoiceUtf8(hexToBytes(hex), "attributes[0]")).toBe(text);
    });

    it.each([
        ["an overlong nul", "c080"],
        ["a C1 lead byte", "c1bf"],
        ["an overlong three-byte form", "e09fbf"],
        ["an overlong four-byte form", "f08fbfbf"],
        ["a high surrogate", "eda080"],
        ["a low surrogate", "edbfbf"],
        ["a point past U+10FFFF", "f4908080"],
        ["the lead byte F5", "f5808080"],
        ["the byte FF", "ff"],
        ["a stray continuation byte", "80"],
        ["a two-byte form cut", "c3"],
        ["a four-byte form cut", "f09f98"],
        ["a form cut by the next character", "c361"],
    ])("refuses %s", (_, hex) => {
        expect(invoiceRefusal(() => decodeInvoiceUtf8(hexToBytes(hex), "attributes[0]"))).toEqual(NOT_UTF8);
    });
});
