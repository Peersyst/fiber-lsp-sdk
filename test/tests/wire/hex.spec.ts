import { hexToBytes } from "@noble/hashes/utils.js";
import { WireError, decodeAnyHexBytes, decodeHexBytes, encodeHexBytes, isWireHex, requireHexBytes } from "../../../src/wire";

const FIELD = { path: "root" };

describe("isWireHex", () => {
    it("accepts 0x-prefixed lowercase hex of the exact byte length", () => {
        expect(isWireHex("0xdeadbeef", 4)).toBe(true);
        expect(isWireHex("0x", 0)).toBe(true);
        expect(isWireHex(`0x${"ab".repeat(33)}`, 33)).toBe(true);
    });

    it("accepts any whole number of bytes when no length is given", () => {
        expect(isWireHex("0x")).toBe(true);
        expect(isWireHex("0xab")).toBe(true);
        expect(isWireHex("0xabcd")).toBe(true);
    });

    it.each([
        ["no prefix", "deadbeef"],
        ["uppercase prefix", "0XDEADBEEF"],
        ["uppercase digits", "0xDEADBEEF"],
        ["an odd digit count", "0xdeadbee"],
        ["a non-hex digit", "0xdeadbeeg"],
        ["surrounding whitespace", " 0xdeadbeef"],
        ["a shorter length", "0xdeadbe"],
        ["a longer length", "0xdeadbeef00"],
        ["an empty string", ""],
    ])("refuses %s", (_, value) => {
        expect(isWireHex(value, 4)).toBe(false);
    });

    it.each([undefined, null, 0xdeadbeef, ["0xdeadbeef"], new Uint8Array(4)])("refuses %p", (value) => {
        expect(isWireHex(value, 4)).toBe(false);
        expect(isWireHex(value)).toBe(false);
    });
});

describe("requireHexBytes", () => {
    it("keeps the wire string", () => {
        expect(requireHexBytes({ ...FIELD, value: "0xdeadbeef" }, 4)).toBe("0xdeadbeef");
    });

    it("refuses naming the size, never the value", () => {
        expect(() => requireHexBytes({ ...FIELD, value: "0xDEADBEEF" }, 4)).toThrow(WireError);
        expect(() => requireHexBytes({ ...FIELD, value: "0xDEADBEEF" }, 4)).toThrow("root must be 4 bytes of 0x-prefixed lowercase hex");
    });
});

describe("decodeHexBytes", () => {
    it("decodes the bytes", () => {
        expect(decodeHexBytes({ ...FIELD, value: "0xdeadbeef" }, 4)).toEqual(hexToBytes("deadbeef"));
    });

    it.each(["deadbeef", "0xdeadbe", "0xDEADBEEF", 4, undefined])("refuses %p", (value) => {
        expect(() => decodeHexBytes({ ...FIELD, value }, 4)).toThrow("root must be 4 bytes of 0x-prefixed lowercase hex");
    });
});

describe("decodeAnyHexBytes", () => {
    it("decodes any whole number of bytes, none included", () => {
        expect(decodeAnyHexBytes({ ...FIELD, value: "0x" })).toEqual(new Uint8Array(0));
        expect(decodeAnyHexBytes({ ...FIELD, value: "0xab" })).toEqual(Uint8Array.of(0xab));
        expect(decodeAnyHexBytes({ ...FIELD, value: `0x${"cd".repeat(100)}` })).toHaveLength(100);
    });

    it.each(["ab", "0xa", "0xAB", "", 1, null])("refuses %p", (value) => {
        expect(() => decodeAnyHexBytes({ ...FIELD, value })).toThrow("root must be whole bytes of 0x-prefixed lowercase hex");
    });
});

describe("encodeHexBytes", () => {
    it("writes 0x-prefixed lowercase hex", () => {
        expect(encodeHexBytes(Uint8Array.of(0xde, 0xad, 0xbe, 0xef))).toBe("0xdeadbeef");
        expect(encodeHexBytes(new Uint8Array(0))).toBe("0x");
    });

    it("round-trips through the decoder", () => {
        const bytes = hexToBytes("00ff10a5");
        expect(decodeHexBytes({ ...FIELD, value: encodeHexBytes(bytes) }, 4)).toEqual(bytes);
    });
});
