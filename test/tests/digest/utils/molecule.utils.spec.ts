import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../../src/digest/digest.types";
import {
    encodeCellInput,
    encodeCellOutput,
    encodeOutPoint,
    encodeRawTransaction,
    encodeScript,
    encodeScriptOpt,
    encodeTransaction,
    moleculeBytes,
    moleculeDynvec,
    moleculeFixvec,
    moleculeTable,
    uint128Le,
    uint32Le,
    uint64Be,
    uint64Le,
} from "../../../../src/digest/utils/molecule.utils";

const ZERO_SCRIPT: Script = { codeHash: new Uint8Array(32), hashType: "data", args: new Uint8Array(0) };

const OUT_POINT = { txHash: new Uint8Array(32).fill(0xaa), index: 7 };

describe("integer encoders", () => {
    it("encodes little-endian at each width", () => {
        expect(bytesToHex(uint32Le(0x01020304))).toBe("04030201");
        expect(bytesToHex(uint64Le(0x0102030405060708n))).toBe("0807060504030201");
        expect(bytesToHex(uint128Le(0x0102030405060708090a0b0c0d0e0f10n))).toBe("100f0e0d0c0b0a090807060504030201");
    });

    it("encodes the commitment number big-endian", () => {
        expect(bytesToHex(uint64Be(0x0102030405060708n))).toBe("0102030405060708");
    });

    it("rejects values outside each width", () => {
        expect(() => uint32Le(-1)).toThrow(RangeError);
        expect(() => uint32Le(2 ** 32)).toThrow(RangeError);
        expect(() => uint64Le(1n << 64n)).toThrow(RangeError);
        expect(() => uint64Be(-1n)).toThrow(RangeError);
        expect(() => uint128Le(1n << 128n)).toThrow(RangeError);
    });
});

describe("moleculeTable", () => {
    it("prefixes the total size and one offset per field", () => {
        expect(bytesToHex(moleculeTable([Uint8Array.of(0xaa), Uint8Array.of(0xbb, 0xcc)]))).toBe("0f0000000c0000000d000000aabbcc");
    });
});

describe("moleculeFixvec", () => {
    it("prefixes the item count only", () => {
        expect(bytesToHex(moleculeFixvec([]))).toBe("00000000");
        expect(bytesToHex(moleculeFixvec([Uint8Array.of(0x01), Uint8Array.of(0x02)]))).toBe("020000000102");
    });
});

describe("moleculeDynvec", () => {
    it("serializes empty as a bare 4-byte size, unlike a fixvec", () => {
        expect(bytesToHex(moleculeDynvec([]))).toBe("04000000");
    });

    it("prefixes the total size and one offset per item", () => {
        expect(bytesToHex(moleculeDynvec([Uint8Array.of(0xaa), Uint8Array.of(0xbb, 0xcc)]))).toBe("0f0000000c0000000d000000aabbcc");
    });
});

describe("moleculeBytes", () => {
    it("prefixes the raw length", () => {
        expect(bytesToHex(moleculeBytes(new Uint8Array(0)))).toBe("00000000");
        expect(bytesToHex(moleculeBytes(Uint8Array.of(0xde, 0xad)))).toBe("02000000dead");
    });
});

describe("encodeScript", () => {
    it("matches the canonical 53-byte default Script", () => {
        expect(bytesToHex(encodeScript(ZERO_SCRIPT))).toBe("35000000100000003000000031000000" + "00".repeat(32) + "00" + "00000000");
    });

    it.each([
        ["data", 0x00],
        ["type", 0x01],
        ["data1", 0x02],
        ["data2", 0x04],
    ] as const)("encodes hash_type %s as 0x%s", (hashType, byte) => {
        expect(encodeScript({ ...ZERO_SCRIPT, hashType })[48]).toBe(byte);
    });

    it("rejects a malformed code hash and an unknown hash type", () => {
        expect(() => encodeScript({ ...ZERO_SCRIPT, codeHash: new Uint8Array(31) })).toThrow(TypeError);
        expect(() => encodeScript({ ...ZERO_SCRIPT, hashType: "data3" as never })).toThrow(TypeError);
        expect(() => encodeScript({ ...ZERO_SCRIPT, args: "00" as never })).toThrow(TypeError);
    });
});

describe("encodeScriptOpt", () => {
    it("serializes None as zero bytes", () => {
        expect(encodeScriptOpt(null)).toHaveLength(0);
        expect(bytesToHex(encodeScriptOpt(ZERO_SCRIPT))).toBe(bytesToHex(encodeScript(ZERO_SCRIPT)));
    });
});

describe("encodeOutPoint", () => {
    it("concatenates the tx hash and the little-endian index", () => {
        expect(bytesToHex(encodeOutPoint(OUT_POINT))).toBe("aa".repeat(32) + "07000000");
    });

    it("rejects a malformed hash and an out-of-range index", () => {
        expect(() => encodeOutPoint({ ...OUT_POINT, txHash: new Uint8Array(33) })).toThrow(TypeError);
        expect(() => encodeOutPoint({ ...OUT_POINT, index: -1 })).toThrow(RangeError);
        expect(() => encodeOutPoint({ ...OUT_POINT, index: 2 ** 32 })).toThrow(RangeError);
    });
});

describe("encodeCellInput", () => {
    it("puts the little-endian since before the out point", () => {
        expect(bytesToHex(encodeCellInput(0x0102030405060708n, OUT_POINT))).toBe("0807060504030201" + "aa".repeat(32) + "07000000");
    });
});

describe("encodeCellOutput", () => {
    it("gives a None type script an offset equal to the total size", () => {
        const output = encodeCellOutput(500n, ZERO_SCRIPT, null);
        const view = new DataView(output.buffer);
        expect(view.getUint32(0, true)).toBe(output.length);
        expect(view.getUint32(12, true)).toBe(output.length);
    });

    it("appends the type script when present", () => {
        const withType = encodeCellOutput(500n, ZERO_SCRIPT, ZERO_SCRIPT);
        const withoutType = encodeCellOutput(500n, ZERO_SCRIPT, null);
        expect(withType.length).toBe(withoutType.length + encodeScript(ZERO_SCRIPT).length);
    });
});

describe("encodeRawTransaction", () => {
    it("matches the canonical 52-byte all-empty RawTransaction", () => {
        const raw = encodeRawTransaction({ version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [] });
        expect(bytesToHex(raw)).toBe(
            "34000000" +
                "1c000000" +
                "20000000" +
                "24000000" +
                "28000000" +
                "2c000000" +
                "30000000" +
                "00000000" +
                "00000000" +
                "00000000" +
                "00000000" +
                "04000000" +
                "04000000",
        );
    });

    it("rejects malformed deps, header deps and inputs", () => {
        const empty = { version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [] };
        expect(() => encodeRawTransaction({ ...empty, cellDeps: [new Uint8Array(36)] })).toThrow(TypeError);
        expect(() => encodeRawTransaction({ ...empty, headerDeps: [new Uint8Array(31)] })).toThrow(TypeError);
        expect(() => encodeRawTransaction({ ...empty, inputs: [new Uint8Array(43)] })).toThrow(TypeError);
    });
});

describe("encodeTransaction", () => {
    it("wraps the raw tx and the witnesses in a two-field table", () => {
        const raw = encodeRawTransaction({ version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [] });
        const transaction = encodeTransaction(raw, [hexToBytes("deadbeef")]);
        expect(bytesToHex(transaction)).toBe(
            "50000000" + "0c000000" + "40000000" + bytesToHex(raw) + "10000000" + "08000000" + "04000000" + "deadbeef",
        );
    });
});
