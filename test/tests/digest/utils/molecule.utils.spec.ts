import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../../src/common";
import { moleculeScript } from "../../../../src/common";
import {
    moleculeCellInput,
    moleculeCellOutput,
    moleculeOutPoint,
    moleculeRawTransaction,
    moleculeTransaction,
    uint64Be,
} from "../../../../src/digest/utils/molecule.utils";

const ZERO_SCRIPT: Script = { codeHash: new Uint8Array(32), hashType: "data", args: new Uint8Array(0) };

const OUT_POINT = { txHash: new Uint8Array(32).fill(0xaa), index: 7 };

describe("uint64Be", () => {
    it("encodes the commitment number big-endian", () => {
        expect(bytesToHex(uint64Be(0x0102030405060708n))).toBe("0102030405060708");
    });

    it("rejects values outside the width", () => {
        expect(() => uint64Be(-1n)).toThrow(RangeError);
        expect(() => uint64Be(1n << 64n)).toThrow(RangeError);
    });
});

describe("moleculeOutPoint", () => {
    it("concatenates the tx hash and the little-endian index", () => {
        expect(bytesToHex(moleculeOutPoint(OUT_POINT))).toBe("aa".repeat(32) + "07000000");
    });

    it("rejects a malformed hash and an out-of-range index", () => {
        expect(() => moleculeOutPoint({ ...OUT_POINT, txHash: new Uint8Array(33) })).toThrow(TypeError);
        expect(() => moleculeOutPoint({ ...OUT_POINT, index: -1 })).toThrow(RangeError);
        expect(() => moleculeOutPoint({ ...OUT_POINT, index: 2 ** 32 })).toThrow(RangeError);
    });
});

describe("moleculeCellInput", () => {
    it("puts the little-endian since before the out point", () => {
        expect(bytesToHex(moleculeCellInput(0x0102030405060708n, OUT_POINT))).toBe("0807060504030201" + "aa".repeat(32) + "07000000");
    });
});

describe("moleculeCellOutput", () => {
    it("gives a None type script an offset equal to the total size", () => {
        const output = moleculeCellOutput(500n, ZERO_SCRIPT, null);
        const view = new DataView(output.buffer);
        expect(view.getUint32(0, true)).toBe(output.length);
        expect(view.getUint32(12, true)).toBe(output.length);
    });

    it("appends the type script when present", () => {
        const withType = moleculeCellOutput(500n, ZERO_SCRIPT, ZERO_SCRIPT);
        const withoutType = moleculeCellOutput(500n, ZERO_SCRIPT, null);
        expect(withType.length).toBe(withoutType.length + moleculeScript(ZERO_SCRIPT).length);
    });
});

describe("moleculeRawTransaction", () => {
    it("matches the canonical 52-byte all-empty RawTransaction", () => {
        const raw = moleculeRawTransaction({ version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [] });
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
        expect(() => moleculeRawTransaction({ ...empty, cellDeps: [new Uint8Array(36)] })).toThrow(TypeError);
        expect(() => moleculeRawTransaction({ ...empty, headerDeps: [new Uint8Array(31)] })).toThrow(TypeError);
        expect(() => moleculeRawTransaction({ ...empty, inputs: [new Uint8Array(43)] })).toThrow(TypeError);
    });
});

describe("moleculeTransaction", () => {
    it("wraps the raw tx and the witnesses in a two-field table", () => {
        const raw = moleculeRawTransaction({ version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [] });
        const transaction = moleculeTransaction(raw, [hexToBytes("deadbeef")]);
        expect(bytesToHex(transaction)).toBe(
            "50000000" + "0c000000" + "40000000" + bytesToHex(raw) + "10000000" + "08000000" + "04000000" + "deadbeef",
        );
    });
});
