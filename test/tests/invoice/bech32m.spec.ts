import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { InvoiceError } from "../../../src/invoice";
import { bytesToInvoiceGroups, decodeInvoiceBech32m, encodeInvoiceBech32m, invoiceGroupsToBytes } from "../../../src/invoice/bech32m";
import { invoiceRefusal } from "../../utils/refusal";

// BIP-350's valid bech32m strings, the lowercase ones.
const BIP350_VALID = [
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
];

describe("decodeInvoiceBech32m", () => {
    it.each(BIP350_VALID)("reads BIP-350's %s and writes it back", (text) => {
        const { hrp, groups } = decodeInvoiceBech32m(text);
        expect(encodeInvoiceBech32m(hrp, groups)).toBe(text);
    });

    it("splits at the last 1 and drops the checksum", () => {
        expect(decodeInvoiceBech32m("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")).toEqual({
            hrp: "abcdef",
            groups: [31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
        });
        expect(decodeInvoiceBech32m("11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8").hrp).toBe(
            "1",
        );
    });

    it.each([
        ["an uppercase string, which BIP-350 holds valid", "A1LQFN3A", "must be lowercase"],
        ["one uppercase character", "a1lqfN3a", "must be lowercase"],
        ["no separator", "qyrz8wqd2c9m", "must have a human-readable part before the last 1"],
        ["an empty human-readable part", "16plkw9", "must have a human-readable part before the last 1"],
        ["another empty human-readable part", "1p2gdwpf", "must have a human-readable part before the last 1"],
        ["b in the data", "y1b0jsk6g", "must write its data in the bech32 charset"],
        ["i in the data", "lt1igcx5c0", "must write its data in the bech32 charset"],
        ["i in the checksum", "mm1crxm3i", "must write its data in the bech32 charset"],
        ["o in the checksum", "au1s5cgom", "must write its data in the bech32 charset"],
        ["a character outside ASCII", "a1lqfn3é", "must write its data in the bech32 charset"],
        ["a checksum of five characters", "in1muywd", "must end with a six-character checksum"],
        ["fewer than six characters after the separator", "a1qqqq", "must end with a six-character checksum"],
        ["a plain bech32 checksum", "a12uel5l", "must carry a valid bech32m checksum"],
        ["one character changed", "a1lqfn3q", "must carry a valid bech32m checksum"],
    ])("refuses %s", (_, text, reason) => {
        expect(invoiceRefusal(() => decodeInvoiceBech32m(text))).toEqual(new InvoiceError("invoice", reason));
    });
});

describe("encodeInvoiceBech32m", () => {
    it("appends the bech32m checksum", () => {
        expect(encodeInvoiceBech32m("a", [])).toBe("a1lqfn3a");
        expect(
            encodeInvoiceBech32m(
                "abcdef",
                [31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
            ),
        ).toBe("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx");
    });
});

describe("five-bit groups", () => {
    it.each([
        ["", []],
        ["ff", [31, 28]],
        ["0102", [0, 4, 1, 0]],
        ["ffffffffff", [31, 31, 31, 31, 31, 31, 31, 31]],
        ["0000000001", [0, 0, 0, 0, 0, 0, 0, 1]],
    ])("regroups %s, most significant bit first, zero padded", (hex, groups) => {
        expect(bytesToInvoiceGroups(hexToBytes(hex))).toEqual(groups);
        expect(bytesToHex(invoiceGroupsToBytes(groups, "data"))).toBe(hex);
    });

    it("refuses padding that is not zero", () => {
        expect(invoiceRefusal(() => invoiceGroupsToBytes([31, 29], "data"))).toEqual(
            new InvoiceError("data", "must be whole bytes with zero padding"),
        );
        expect(invoiceRefusal(() => invoiceGroupsToBytes([0, 1], "data"))).toEqual(
            new InvoiceError("data", "must be whole bytes with zero padding"),
        );
    });

    it("refuses a whole group of padding, so one byte string has one form", () => {
        expect(invoiceRefusal(() => invoiceGroupsToBytes([31, 28, 0], "data"))).toEqual(
            new InvoiceError("data", "must be whole bytes with zero padding"),
        );
        expect(invoiceRefusal(() => invoiceGroupsToBytes([0], "signature"))).toEqual(
            new InvoiceError("signature", "must be whole bytes with zero padding"),
        );
    });
});
