import { bytesToHex } from "@noble/hashes/utils.js";
import type { Script } from "../../../../src/common";
import {
    moleculeBytes,
    moleculeDynvec,
    moleculeFixvec,
    moleculeScript,
    moleculeScriptOpt,
    moleculeTable,
    uint128Le,
    uint32Le,
    uint64Le,
} from "../../../../src/common/utils/molecule.utils";

const ZERO_SCRIPT: Script = { codeHash: new Uint8Array(32), hashType: "data", args: new Uint8Array(0) };

describe("integer encoders", () => {
    it("encodes little-endian at each width", () => {
        expect(bytesToHex(uint32Le(0x01020304))).toBe("04030201");
        expect(bytesToHex(uint64Le(0x0102030405060708n))).toBe("0807060504030201");
        expect(bytesToHex(uint128Le(0x0102030405060708090a0b0c0d0e0f10n))).toBe("100f0e0d0c0b0a090807060504030201");
    });

    it("rejects values outside each width", () => {
        expect(() => uint32Le(-1)).toThrow(RangeError);
        expect(() => uint32Le(2 ** 32)).toThrow(RangeError);
        expect(() => uint64Le(1n << 64n)).toThrow(RangeError);
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
describe("moleculeScript", () => {
    it("matches the canonical 53-byte default Script", () => {
        expect(bytesToHex(moleculeScript(ZERO_SCRIPT))).toBe("35000000100000003000000031000000" + "00".repeat(32) + "00" + "00000000");
    });

    it.each([
        ["data", 0x00],
        ["type", 0x01],
        ["data1", 0x02],
        ["data2", 0x04],
    ] as const)("encodes hash_type %s as 0x%s", (hashType, byte) => {
        expect(moleculeScript({ ...ZERO_SCRIPT, hashType })[48]).toBe(byte);
    });

    it("rejects a malformed code hash and an unknown hash type", () => {
        expect(() => moleculeScript({ ...ZERO_SCRIPT, codeHash: new Uint8Array(31) })).toThrow(TypeError);
        expect(() => moleculeScript({ ...ZERO_SCRIPT, hashType: "data3" as never })).toThrow(TypeError);
        expect(() => moleculeScript({ ...ZERO_SCRIPT, args: "00" as never })).toThrow(TypeError);
    });

    it("names the fields after the path it is given, and refuses a script that is not an object", () => {
        expect(() => moleculeScript({ ...ZERO_SCRIPT, hashType: "data3" as never })).toThrow(
            new TypeError("script.hashType must be one of data, type, data1, data2"),
        );
        expect(() => moleculeScript({ ...ZERO_SCRIPT, codeHash: new Uint8Array(31) }, "lock")).toThrow(
            new TypeError("lock.codeHash must be 32 bytes, got 31"),
        );
        expect(() => moleculeScript(undefined as never, "lock")).toThrow(new TypeError("lock must be an object"));
    });
});
describe("moleculeScriptOpt", () => {
    it("serializes None as zero bytes", () => {
        expect(moleculeScriptOpt(null)).toHaveLength(0);
        expect(bytesToHex(moleculeScriptOpt(ZERO_SCRIPT))).toBe(bytesToHex(moleculeScript(ZERO_SCRIPT)));
    });
});
