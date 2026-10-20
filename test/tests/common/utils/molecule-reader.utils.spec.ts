import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { MoleculeFault, MoleculeRefuse } from "../../../../src/common";
import {
    moleculeFaultReason,
    readMoleculeBytes,
    readMoleculeDynvec,
    readMoleculeFixed,
    readMoleculeScript,
    readMoleculeTable,
    readMoleculeUint,
    readMoleculeUnion,
} from "../../../../src/common";

class Refused extends Error {
    constructor(
        readonly path: string,
        readonly fault: MoleculeFault,
    ) {
        super(path);
    }
}

const refuse: MoleculeRefuse = (path, fault) => {
    throw new Refused(path, fault);
};

function refused(step: () => unknown): { path: string; fault: MoleculeFault } {
    try {
        step();
    } catch (error) {
        if (error instanceof Refused) return { path: error.path, fault: error.fault };
        throw error;
    }
    throw new Error("the read did not refuse");
}

const hexes = (items: Uint8Array[]): string[] => items.map(bytesToHex);

const NAMES = { codeHash: "c", hashType: "h", args: "a" };
const CODE_HASH = "ab".repeat(32);
// A `Script` table: size 0x37, offsets 0x10, 0x30, 0x31, then its three fields.
const SCRIPT_HEADER = "37000000" + "10000000" + "30000000" + "31000000";
const SCRIPT = SCRIPT_HEADER + CODE_HASH + "01" + "020000000102";

describe("moleculeFaultReason", () => {
    it.each<[MoleculeFault, string]>([
        [{ kind: "size" }, "must be exactly as long as its size says"],
        [{ kind: "header" }, "must have a whole header"],
        [{ kind: "fieldCount", fields: 1 }, "must have exactly 1 field"],
        [{ kind: "fieldCount", fields: 0 }, "must have exactly 0 fields"],
        [{ kind: "fieldCount", fields: 3 }, "must have exactly 3 fields"],
        [{ kind: "offsets" }, "must have offsets in order"],
        [{ kind: "fixedSize", bytes: 1 }, "must be exactly 1 byte"],
        [{ kind: "fixedSize", bytes: 32 }, "must be exactly 32 bytes"],
        [{ kind: "bytesLength" }, "must be exactly as long as its length says"],
        [{ kind: "itemIdMissing" }, "must start with an item id"],
        [{ kind: "itemId", items: 11 }, "must have an item id below 11"],
        [{ kind: "hashType" }, "must be one of data, type, data1, data2"],
    ])("words %p", (fault, reason) => {
        expect(moleculeFaultReason(fault)).toBe(reason);
    });
});

describe("readMoleculeTable", () => {
    it("splits the fields at their offsets", () => {
        expect(hexes(readMoleculeTable(hexToBytes("0f0000000c0000000d000000aabbcc"), 2, "t", refuse))).toEqual(["aa", "bbcc"]);
    });

    it("reads fields that are all empty, the first offset at the end", () => {
        expect(hexes(readMoleculeTable(hexToBytes("0c0000000c0000000c000000"), 2, "t", refuse))).toEqual(["", ""]);
    });

    it("reads a table of no fields as its bare size", () => {
        expect(readMoleculeTable(hexToBytes("04000000"), 0, "t", refuse)).toEqual([]);
    });

    it("reads a one-field table, its first offset at the smallest header", () => {
        expect(hexes(readMoleculeTable(hexToBytes("0900000008000000aa"), 1, "t", refuse))).toEqual(["aa"]);
    });

    it("returns views over the input, not copies", () => {
        const bytes = hexToBytes("0900000008000000aa");
        expect(readMoleculeTable(bytes, 1, "t", refuse)[0]?.buffer).toBe(bytes.buffer);
    });

    it.each<[string, string, MoleculeFault]>([
        ["no bytes", "", { kind: "size" }],
        ["three bytes", "040000", { kind: "size" }],
        ["a size one short", "0e0000000c0000000d000000aabbcc", { kind: "size" }],
        ["a size one long", "100000000c0000000d000000aabbcc", { kind: "size" }],
        ["a bare size where fields are due", "04000000", { kind: "fieldCount", fields: 2 }],
        ["a size and three bytes of offset", "070000000c0000", { kind: "header" }],
        ["a first offset one past a multiple of four", "0d0000000d000000aabbccdd00", { kind: "header" }],
        ["a first offset at the bare size", "0800000004000000", { kind: "header" }],
        ["a first offset past the end", "0c0000001000000010000000", { kind: "header" }],
        ["one field less", "0900000008000000aa", { kind: "fieldCount", fields: 2 }],
        ["one field more", "13000000100000001100000012000000aabbcc", { kind: "fieldCount", fields: 2 }],
        ["offsets one out of order", "0e0000000c0000000b000000aabb", { kind: "offsets" }],
        ["a last offset one past the end", "0e0000000c0000000f000000aabb", { kind: "offsets" }],
    ])("refuses %s", (_, hex, fault) => {
        expect(refused(() => readMoleculeTable(hexToBytes(hex), 2, "t", refuse))).toEqual({ path: "t", fault });
    });

    it("refuses the field count before it reads the offsets, as molecule's verifier does", () => {
        expect(refused(() => readMoleculeTable(hexToBytes("13000000100000001400000012000000aabbcc"), 2, "t", refuse))).toEqual({
            path: "t",
            fault: { kind: "fieldCount", fields: 2 },
        });
    });
});

describe("readMoleculeDynvec", () => {
    it("reads an empty dynvec as its bare size", () => {
        expect(readMoleculeDynvec(hexToBytes("04000000"), "v", refuse)).toEqual([]);
    });

    it("splits whatever number of items its header delimits", () => {
        expect(hexes(readMoleculeDynvec(hexToBytes("0e0000000c0000000d000000aabb"), "v", refuse))).toEqual(["aa", "bb"]);
        expect(hexes(readMoleculeDynvec(hexToBytes("0900000008000000aa"), "v", refuse))).toEqual(["aa"]);
    });

    it.each<[string, string, MoleculeFault]>([
        ["three bytes", "040000", { kind: "size" }],
        ["a size one long", "0f0000000c0000000d000000aabb", { kind: "size" }],
        ["a size and half an offset", "060000000c00", { kind: "header" }],
        ["a first offset past the end", "080000000c000000", { kind: "header" }],
        ["offsets out of order", "0e0000000c0000000b000000aabb", { kind: "offsets" }],
    ])("refuses %s", (_, hex, fault) => {
        expect(refused(() => readMoleculeDynvec(hexToBytes(hex), "v", refuse))).toEqual({ path: "v", fault });
    });
});

describe("readMoleculeFixed", () => {
    it("returns bytes of exactly the size", () => {
        expect(bytesToHex(readMoleculeFixed(hexToBytes("aabb"), 2, "f", refuse))).toBe("aabb");
        expect(readMoleculeFixed(new Uint8Array(0), 0, "f", refuse)).toEqual(new Uint8Array(0));
    });

    it.each(["aa", "aabbcc", ""])("refuses %p for two bytes", (hex) => {
        expect(refused(() => readMoleculeFixed(hexToBytes(hex), 2, "f", refuse))).toEqual({
            path: "f",
            fault: { kind: "fixedSize", bytes: 2 },
        });
    });
});

describe("readMoleculeBytes", () => {
    it("returns the data after the length", () => {
        expect(bytesToHex(readMoleculeBytes(hexToBytes("020000000102"), "b", refuse))).toBe("0102");
    });

    it("reads empty data", () => {
        expect(readMoleculeBytes(hexToBytes("00000000"), "b", refuse)).toEqual(new Uint8Array(0));
    });

    it.each([
        ["a length one short", "010000000102"],
        ["a length one long", "030000000102"],
        ["no length", ""],
        ["three bytes of length", "000000"],
    ])("refuses %s", (_, hex) => {
        expect(refused(() => readMoleculeBytes(hexToBytes(hex), "b", refuse))).toEqual({ path: "b", fault: { kind: "bytesLength" } });
    });
});

describe("readMoleculeUint", () => {
    it("reads little-endian", () => {
        expect(readMoleculeUint(hexToBytes("0001000000000000"), 8, "u", refuse)).toBe(256n);
        expect(readMoleculeUint(hexToBytes("ff".repeat(16)), 16, "u", refuse)).toBe((1n << 128n) - 1n);
        expect(readMoleculeUint(hexToBytes("00".repeat(8)), 8, "u", refuse)).toBe(0n);
    });

    it.each(["00".repeat(7), "00".repeat(9)])("refuses %p as a u64", (hex) => {
        expect(refused(() => readMoleculeUint(hexToBytes(hex), 8, "u", refuse))).toEqual({
            path: "u",
            fault: { kind: "fixedSize", bytes: 8 },
        });
    });
});

describe("readMoleculeUnion", () => {
    const ITEMS = ["a", "b", "c"] as const;

    it("selects the item at its id, the rest of the bytes its body", () => {
        expect(readMoleculeUnion(hexToBytes("00000000aa"), ITEMS, "u", refuse)).toEqual({ name: "a", item: hexToBytes("aa") });
        expect(readMoleculeUnion(hexToBytes("02000000"), ITEMS, "u", refuse)).toEqual({ name: "c", item: new Uint8Array(0) });
    });

    it("refuses the first id past the schema", () => {
        expect(refused(() => readMoleculeUnion(hexToBytes("03000000"), ITEMS, "u", refuse))).toEqual({
            path: "u",
            fault: { kind: "itemId", items: 3 },
        });
    });

    it.each(["", "000000"])("refuses %p, too short for an id", (hex) => {
        expect(refused(() => readMoleculeUnion(hexToBytes(hex), ITEMS, "u", refuse))).toEqual({
            path: "u",
            fault: { kind: "itemIdMissing" },
        });
    });
});

describe("readMoleculeScript", () => {
    it("reads the script into bytes of its own", () => {
        const script = readMoleculeScript(hexToBytes(SCRIPT), "s", NAMES, refuse);
        expect(script).toEqual({ codeHash: hexToBytes(CODE_HASH), hashType: "type", args: hexToBytes("0102") });
        expect(script.codeHash.buffer.byteLength).toBe(32);
        expect(script.args.buffer.byteLength).toBe(2);
    });

    it.each([
        ["00", "data"],
        ["01", "type"],
        ["02", "data1"],
        ["04", "data2"],
    ] as const)("maps the hash type byte %s to %s", (byte, hashType) => {
        expect(readMoleculeScript(hexToBytes(SCRIPT_HEADER + CODE_HASH + byte + "020000000102"), "s", NAMES, refuse).hashType).toBe(
            hashType,
        );
    });

    it("refuses a table of the wrong field count at the script's path", () => {
        expect(refused(() => readMoleculeScript(hexToBytes("0e0000000c0000000d000000aabb"), "s", NAMES, refuse))).toEqual({
            path: "s",
            fault: { kind: "fieldCount", fields: 3 },
        });
    });

    it("refuses a code hash of 31 bytes under the caller's name for it", () => {
        const hex = "36000000" + "10000000" + "2f000000" + "30000000" + "ab".repeat(31) + "01" + "020000000102";
        expect(refused(() => readMoleculeScript(hexToBytes(hex), "s", NAMES, refuse))).toEqual({
            path: "s.c",
            fault: { kind: "fixedSize", bytes: 32 },
        });
    });

    it("refuses a hash type of two bytes under the caller's name for it", () => {
        const hex = "38000000" + "10000000" + "30000000" + "32000000" + CODE_HASH + "0100" + "020000000102";
        expect(refused(() => readMoleculeScript(hexToBytes(hex), "s", NAMES, refuse))).toEqual({
            path: "s.h",
            fault: { kind: "fixedSize", bytes: 1 },
        });
    });

    it.each(["03", "05", "ff"])("refuses the hash type byte %s, which CKB does not define", (byte) => {
        expect(
            refused(() => readMoleculeScript(hexToBytes(SCRIPT_HEADER + CODE_HASH + byte + "020000000102"), "s", NAMES, refuse)),
        ).toEqual({
            path: "s.h",
            fault: { kind: "hashType" },
        });
    });

    it("refuses args whose length is one long under the caller's name for them", () => {
        expect(
            refused(() => readMoleculeScript(hexToBytes(SCRIPT_HEADER + CODE_HASH + "01" + "030000000102"), "s", NAMES, refuse)),
        ).toEqual({
            path: "s.a",
            fault: { kind: "bytesLength" },
        });
    });

    it("refuses the fields in their order: the code hash before an undefined hash type, the hash type before the args", () => {
        const shortHash = "36000000" + "10000000" + "2f000000" + "30000000" + "ab".repeat(31) + "ff" + "030000000102";
        expect(refused(() => readMoleculeScript(hexToBytes(shortHash), "s", NAMES, refuse)).path).toBe("s.c");
        expect(
            refused(() => readMoleculeScript(hexToBytes(SCRIPT_HEADER + CODE_HASH + "ff" + "030000000102"), "s", NAMES, refuse)).path,
        ).toBe("s.h");
    });
});
