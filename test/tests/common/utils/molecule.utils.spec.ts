import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../../src/common";
import {
    decodeMoleculeScript,
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

describe("decodeMoleculeScript", () => {
    const HEADER = "35000000" + "10000000" + "30000000" + "31000000";
    const CODE_HASH = "11".repeat(32);
    const SCRIPT = HEADER + CODE_HASH + "01" + "00000000";
    const decode = (hex: string, name?: string) => decodeMoleculeScript(hexToBytes(hex), name);
    const SIZE_MESSAGE = new TypeError("script must be exactly as long as its size says");
    const FIELDS_MESSAGE = new TypeError("script must have exactly 3 fields");
    const HEADER_MESSAGE = new TypeError("script must have a whole header");
    const OFFSETS_MESSAGE = new TypeError("script must have offsets in order");
    const ARGS_MESSAGE = new TypeError("script.args must be exactly as long as its length says");

    it("reads what moleculeScript writes, empty args", () => {
        const script: Script = { codeHash: new Uint8Array(32).fill(0x11), hashType: "type", args: new Uint8Array(0) };
        expect(bytesToHex(moleculeScript(script))).toBe(SCRIPT);
        expect(decode(SCRIPT)).toEqual(script);
    });

    it("reads long args", () => {
        const args = Uint8Array.from({ length: 300 }, (_, index) => index % 256);
        const script: Script = { codeHash: new Uint8Array(32).fill(0x22), hashType: "data1", args };
        expect(decodeMoleculeScript(moleculeScript(script))).toEqual(script);
    });

    it.each([
        ["data", "00"],
        ["type", "01"],
        ["data1", "02"],
        ["data2", "04"],
    ] as const)("reads hash_type %s", (hashType, byte) => {
        const hex = "36000000" + "10000000" + "30000000" + "31000000" + CODE_HASH + byte + "0100000007";
        const script = decode(hex);
        expect(script).toEqual({ codeHash: new Uint8Array(32).fill(0x11), hashType, args: Uint8Array.of(7) });
        expect(bytesToHex(moleculeScript(script))).toBe(hex);
    });

    it("returns copies, not views over the input", () => {
        const bytes = hexToBytes(SCRIPT);
        const script = decodeMoleculeScript(bytes);
        bytes.fill(0xff);
        expect(script.codeHash).toEqual(new Uint8Array(32).fill(0x11));
    });

    it("names the fields after the path it is given", () => {
        expect(() => decode("00", "lock")).toThrow(new TypeError("lock must be exactly as long as its size says"));
        expect(() => decode(SCRIPT.replace(CODE_HASH + "01", "11".repeat(32) + "09"), "lock")).toThrow(
            new TypeError("lock.hashType must be one of data, type, data1, data2"),
        );
    });

    it("refuses bytes that are not a Uint8Array", () => {
        expect(() => decodeMoleculeScript("35000000" as never)).toThrow(new TypeError("script must be a Uint8Array"));
        expect(() => decodeMoleculeScript(undefined as never, "lock")).toThrow(new TypeError("lock must be a Uint8Array"));
    });

    it("refuses a total size that is not the byte length", () => {
        expect(() => decode(SCRIPT.replace("35000000", "34000000"))).toThrow(SIZE_MESSAGE);
        expect(() => decode(SCRIPT.replace("35000000", "36000000"))).toThrow(SIZE_MESSAGE);
        expect(() => decode("")).toThrow(SIZE_MESSAGE);
        expect(() => decode("350000")).toThrow(SIZE_MESSAGE);
    });

    it("refuses a header shorter than the size and three offsets", () => {
        expect(() => decode("04000000")).toThrow(FIELDS_MESSAGE);
        expect(() => decode("0800000010000000")).toThrow(HEADER_MESSAGE);
        expect(() => decode("0a00000010000000aabb")).toThrow(HEADER_MESSAGE);
        expect(() => decode("0c000000100000003000aabb")).toThrow(HEADER_MESSAGE);
    });

    it("refuses a field count other than 3", () => {
        const two = "2d000000" + "0c000000" + "2c000000" + CODE_HASH + "01";
        expect(() => decode(two)).toThrow(FIELDS_MESSAGE);
        const four = "39000000" + "14000000" + "34000000" + "35000000" + "35000000" + CODE_HASH + "01" + "00000000";
        expect(() => decode(four)).toThrow(FIELDS_MESSAGE);
    });

    it("refuses a first offset that is not 16", () => {
        expect(() => decode(SCRIPT.replace("35000000" + "10000000", "35000000" + "11000000"))).toThrow(HEADER_MESSAGE);
        expect(() => decode(SCRIPT.replace("35000000" + "10000000", "35000000" + "0c000000"))).toThrow(FIELDS_MESSAGE);
        expect(() => decode(SCRIPT.replace("35000000" + "10000000", "35000000" + "14000000"))).toThrow(FIELDS_MESSAGE);
    });

    it("refuses offsets that descend", () => {
        expect(() => decode(SCRIPT.replace("30000000" + "31000000", "31000000" + "30000000"))).toThrow(OFFSETS_MESSAGE);
        expect(() => decode(SCRIPT.replace("30000000" + "31000000", "32000000" + "31000000"))).toThrow(OFFSETS_MESSAGE);
    });

    it("refuses an offset past the end", () => {
        expect(() => decode(SCRIPT.replace("31000000" + CODE_HASH, "36000000" + CODE_HASH))).toThrow(OFFSETS_MESSAGE);
        expect(() => decode(SCRIPT.replace("30000000" + "31000000", "30000000" + "ffffffff"))).toThrow(OFFSETS_MESSAGE);
    });

    it("refuses a code hash that is not 32 bytes", () => {
        const short = "34000000" + "10000000" + "2f000000" + "30000000" + "11".repeat(31) + "01" + "00000000";
        expect(() => decode(short)).toThrow(new TypeError("script.codeHash must be exactly 32 bytes"));
        const long = "36000000" + "10000000" + "31000000" + "32000000" + "11".repeat(33) + "01" + "00000000";
        expect(() => decode(long)).toThrow(new TypeError("script.codeHash must be exactly 32 bytes"));
    });

    it("refuses a hash_type that is not one byte", () => {
        const empty = "34000000" + "10000000" + "30000000" + "30000000" + CODE_HASH + "00000000";
        expect(() => decode(empty)).toThrow(new TypeError("script.hashType must be exactly 1 byte"));
        const two = "36000000" + "10000000" + "30000000" + "32000000" + CODE_HASH + "0100" + "00000000";
        expect(() => decode(two)).toThrow(new TypeError("script.hashType must be exactly 1 byte"));
    });

    it.each(["03", "05", "ff"])("refuses the hash_type byte 0x%s, which moleculeScript never writes", (byte) => {
        expect(() => decode(SCRIPT.replace(CODE_HASH + "01", CODE_HASH + byte))).toThrow(
            new TypeError("script.hashType must be one of data, type, data1, data2"),
        );
    });

    it("refuses args whose length prefix disagrees with the slot", () => {
        const withArgs = "37000000" + "10000000" + "30000000" + "31000000" + CODE_HASH + "01" + "020000000102";
        expect(decode(withArgs).args).toEqual(Uint8Array.of(1, 2));
        expect(() => decode(withArgs.replace("020000000102", "010000000102"))).toThrow(ARGS_MESSAGE);
        expect(() => decode(withArgs.replace("020000000102", "030000000102"))).toThrow(ARGS_MESSAGE);
    });

    it("refuses an args slot shorter than its length prefix", () => {
        const noArgs = "31000000" + "10000000" + "30000000" + "31000000" + CODE_HASH + "01";
        expect(() => decode(noArgs)).toThrow(ARGS_MESSAGE);
        const partial = "33000000" + "10000000" + "30000000" + "31000000" + CODE_HASH + "01" + "0000";
        expect(() => decode(partial)).toThrow(ARGS_MESSAGE);
    });

    it("refuses trailing bytes, past the size and inside it", () => {
        expect(() => decode(SCRIPT + "00")).toThrow(SIZE_MESSAGE);
        expect(() => decode("36000000" + SCRIPT.slice(8) + "00")).toThrow(ARGS_MESSAGE);
    });
});
