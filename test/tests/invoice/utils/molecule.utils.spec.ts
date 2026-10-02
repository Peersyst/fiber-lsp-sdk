import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../../src/common";
import { InvoiceError } from "../../../../src/invoice";
import {
    readInvoiceMoleculeBytes,
    readInvoiceMoleculeDynvec,
    readInvoiceMoleculeFixed,
    readInvoiceMoleculeScript,
    readInvoiceMoleculeTable,
    readInvoiceMoleculeUint,
    readInvoiceMoleculeUnion,
} from "../../../../src/invoice/utils/molecule.utils";
import { invoiceRefusal } from "../../../utils/refusal";

const hexes = (items: Uint8Array[]): string[] => items.map(bytesToHex);

const CODE_HASH = "ab".repeat(32);

// A `Script` table: size 0x38, offsets 0x10, 0x30, 0x31, the code hash, the hash type byte, then `Bytes` of 0102.
const scriptHex = (hashType: string, codeHash = CODE_HASH, args = "020000000102"): string => {
    const fields = [codeHash, hashType, args];
    const header = 4 * (fields.length + 1);
    const sizes = fields.map((field) => field.length / 2);
    const le = (value: number): string => bytesToHex(Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, 0, 0));
    const offsets = sizes.reduce<number[]>((all, size, index) => [...all, (all[index] ?? header) + size], [header]);
    return le(offsets[fields.length] ?? 0) + offsets.slice(0, -1).map(le).join("") + fields.join("");
};

describe("readInvoiceMoleculeTable", () => {
    it("splits the fields at their offsets", () => {
        expect(hexes(readInvoiceMoleculeTable(hexToBytes("0f0000000c0000000d000000aabbcc"), 2, "t"))).toEqual(["aa", "bbcc"]);
    });

    it("reads a field that is empty, its offset equal to the next one", () => {
        expect(hexes(readInvoiceMoleculeTable(hexToBytes("0d0000000c0000000c000000aa"), 2, "t"))).toEqual(["", "aa"]);
    });

    it.each([
        ["shorter than its size", "100000000c0000000d000000aabbcc", "must be exactly as long as its size says"],
        ["longer than its size", "0e0000000c0000000d000000aabbcc", "must be exactly as long as its size says"],
        ["shorter than a size", "0f0000", "must be exactly as long as its size says"],
        ["a size and no offsets", "04000000", "must have exactly 2 fields"],
        ["a size and half an offset", "060000000c00", "must have a whole header"],
        ["a first offset that is not a multiple of four", "0d0000000900000000aabbccdd", "must have a whole header"],
        ["a first offset inside the size", "0800000004000000", "must have a whole header"],
        ["a first offset past the end", "080000000c000000", "must have a whole header"],
        ["one field more", "13000000100000001100000012000000aabbcc", "must have exactly 2 fields"],
        ["offsets out of order", "0e0000000c0000000b000000aabb", "must have offsets in order"],
    ])("refuses a table %s", (_, hex, reason) => {
        expect(invoiceRefusal(() => readInvoiceMoleculeTable(hexToBytes(hex), 2, "data"))).toEqual(new InvoiceError("data", reason));
    });

    it("says one field when a table has one", () => {
        expect(invoiceRefusal(() => readInvoiceMoleculeTable(hexToBytes("0f0000000c0000000d000000aabbcc"), 1, "data")).reason).toBe(
            "must have exactly 1 field",
        );
    });
});

describe("readInvoiceMoleculeDynvec", () => {
    it("reads an empty dynvec as its bare size", () => {
        expect(readInvoiceMoleculeDynvec(hexToBytes("04000000"), "v")).toEqual([]);
    });

    it("reads any number of items", () => {
        expect(hexes(readInvoiceMoleculeDynvec(hexToBytes("0f0000000c0000000d000000aabbcc"), "v"))).toEqual(["aa", "bbcc"]);
        expect(hexes(readInvoiceMoleculeDynvec(hexToBytes("0d00000008000000aabbccddee"), "v"))).toEqual(["aabbccddee"]);
    });

    it("refuses a dynvec whose size is not its length", () => {
        expect(invoiceRefusal(() => readInvoiceMoleculeDynvec(hexToBytes("0600000000"), "data.attributes"))).toEqual(
            new InvoiceError("data.attributes", "must be exactly as long as its size says"),
        );
    });
});

describe("readInvoiceMoleculeBytes", () => {
    it("reads the data after its length", () => {
        expect(bytesToHex(readInvoiceMoleculeBytes(hexToBytes("02000000aabb"), "b"))).toBe("aabb");
        expect(bytesToHex(readInvoiceMoleculeBytes(hexToBytes("00000000"), "b"))).toBe("");
    });

    it.each([
        ["more data than its length", "01000000aabb"],
        ["less data than its length", "03000000aabb"],
        ["no length", "0200"],
    ])("refuses %s", (_, hex) => {
        expect(invoiceRefusal(() => readInvoiceMoleculeBytes(hexToBytes(hex), "value"))).toEqual(
            new InvoiceError("value", "must be exactly as long as its length says"),
        );
    });
});

describe("readInvoiceMoleculeFixed and readInvoiceMoleculeUint", () => {
    it("read a value of exactly its size, integers little-endian", () => {
        expect(bytesToHex(readInvoiceMoleculeFixed(hexToBytes("aabb"), 2, "f"))).toBe("aabb");
        expect(readInvoiceMoleculeUint(hexToBytes("0807060504030201"), 8, "u")).toBe(0x0102030405060708n);
        expect(readInvoiceMoleculeUint(hexToBytes("ff".repeat(16)), 16, "u")).toBe((1n << 128n) - 1n);
    });

    it("refuse a value of another size, either way", () => {
        expect(invoiceRefusal(() => readInvoiceMoleculeFixed(hexToBytes("aabb"), 3, "f"))).toEqual(
            new InvoiceError("f", "must be exactly 3 bytes"),
        );
        expect(invoiceRefusal(() => readInvoiceMoleculeUint(hexToBytes("010203040506070809"), 8, "u"))).toEqual(
            new InvoiceError("u", "must be exactly 8 bytes"),
        );
    });
});

describe("readInvoiceMoleculeUnion", () => {
    const ITEMS = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];

    it("names the item its id selects and leaves the item to its reader", () => {
        const { name, item } = readInvoiceMoleculeUnion(hexToBytes("09000000aabb"), ITEMS, "u");
        expect(name).toBe("j");
        expect(bytesToHex(item)).toBe("aabb");
    });

    it("refuses an id past the schema's items and a union too short for an id", () => {
        expect(invoiceRefusal(() => readInvoiceMoleculeUnion(hexToBytes("0a000000"), ITEMS, "u"))).toEqual(
            new InvoiceError("u", "must have an item id below 10"),
        );
        expect(invoiceRefusal(() => readInvoiceMoleculeUnion(hexToBytes("000000"), ITEMS, "u"))).toEqual(
            new InvoiceError("u", "must start with an item id"),
        );
    });
});

describe("readInvoiceMoleculeScript", () => {
    it.each([
        ["00", "data"],
        ["01", "type"],
        ["02", "data1"],
        ["04", "data2"],
    ] as const)("reads hash type byte %s as %s", (byte, hashType) => {
        const expected: Script = { codeHash: hexToBytes(CODE_HASH), hashType, args: hexToBytes("0102") };
        expect(readInvoiceMoleculeScript(hexToBytes(scriptHex(byte)), "s")).toEqual(expected);
    });

    it.each(["03", "05", "09", "ff"])("refuses hash type byte %s, which CKB does not define", (byte) => {
        expect(invoiceRefusal(() => readInvoiceMoleculeScript(hexToBytes(scriptHex(byte)), "udtScript"))).toEqual(
            new InvoiceError("udtScript.hashType", "must be one of data, type, data1, data2"),
        );
    });

    it("refuses each field of the wrong form", () => {
        expect(invoiceRefusal(() => readInvoiceMoleculeScript(hexToBytes(scriptHex("01", "ab".repeat(31))), "s"))).toEqual(
            new InvoiceError("s.codeHash", "must be exactly 32 bytes"),
        );
        expect(invoiceRefusal(() => readInvoiceMoleculeScript(hexToBytes(scriptHex("0100")), "s"))).toEqual(
            new InvoiceError("s.hashType", "must be exactly 1 byte"),
        );
        expect(invoiceRefusal(() => readInvoiceMoleculeScript(hexToBytes(scriptHex("01", CODE_HASH, "030000000102")), "s"))).toEqual(
            new InvoiceError("s.args", "must be exactly as long as its length says"),
        );
    });
});
