import { hexToBytes } from "@noble/hashes/utils.js";
import {
    WireError,
    assertWireHexBytes,
    decodeAnyHexBytes,
    decodeBareHexBytes,
    decodeHexBytes,
    encodeAnyHexBytes,
    encodeBareHexBytes,
    encodeHexBytes,
    isWireHex,
    requireHexBytes,
} from "../../../src/wire";
import { refusal } from "../../utils/refusal";

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
    it("writes 0x-prefixed lowercase hex of the exact length", () => {
        expect(encodeHexBytes("hash", Uint8Array.of(0xde, 0xad, 0xbe, 0xef), 4)).toBe("0xdeadbeef");
        expect(encodeHexBytes("hash", new Uint8Array(0), 0)).toBe("0x");
    });

    it("round-trips through the decoder", () => {
        const bytes = hexToBytes("00ff10a5");
        expect(decodeHexBytes({ ...FIELD, value: encodeHexBytes("hash", bytes, 4) }, 4)).toEqual(bytes);
    });

    it.each([3, 5])("refuses %i bytes where 4 are due, naming the value", (length) => {
        expect(() => encodeHexBytes("hash", new Uint8Array(length), 4)).toThrow(new TypeError(`hash must be 4 bytes, got ${length}`));
    });

    it.each(["0xdeadbeef", [0xde, 0xad, 0xbe, 0xef], undefined])("refuses %p as not bytes", (value) => {
        expect(() => encodeHexBytes("hash", value as unknown as Uint8Array, 4)).toThrow(new TypeError("hash must be a Uint8Array"));
    });
});

describe("encodeAnyHexBytes", () => {
    it("writes 0x-prefixed lowercase hex of any length, 0x for none", () => {
        expect(encodeAnyHexBytes("args", Uint8Array.of(0xde, 0xad, 0xbe, 0xef))).toBe("0xdeadbeef");
        expect(encodeAnyHexBytes("args", Uint8Array.of(0x00))).toBe("0x00");
        expect(encodeAnyHexBytes("args", new Uint8Array(0))).toBe("0x");
    });

    it("round-trips through the any-length decoder", () => {
        const bytes = hexToBytes("00ff10a5ee");
        expect(decodeAnyHexBytes({ ...FIELD, value: encodeAnyHexBytes("args", bytes) })).toEqual(bytes);
    });

    it.each(["0xdeadbeef", "", [0xde], new ArrayBuffer(4), null])("refuses %p as not bytes", (value) => {
        expect(() => encodeAnyHexBytes("args", value as unknown as Uint8Array)).toThrow(new TypeError("args must be a Uint8Array"));
    });
});

describe("decodeBareHexBytes", () => {
    const PUBKEY = `02${"ab".repeat(32)}`;
    const FORM = "root must be 33 bytes of lowercase hex without a 0x prefix";

    it("decodes lowercase hex without a prefix", () => {
        expect(decodeBareHexBytes({ ...FIELD, value: PUBKEY }, 33)).toEqual(hexToBytes(PUBKEY));
    });

    it.each([
        ["a 0x prefix", `0x${PUBKEY}`],
        ["uppercase digits", PUBKEY.toUpperCase()],
        ["an odd digit count", PUBKEY.slice(1)],
        ["one byte short", PUBKEY.slice(2)],
        ["one byte long", `${PUBKEY}00`],
        ["an empty string", ""],
        ["a non-hex digit", `0g${"ab".repeat(32)}`],
    ])("refuses %s", (_, value) => {
        expect(refusal(() => decodeBareHexBytes({ ...FIELD, value }, 33)).message).toBe(FORM);
    });

    it.each([undefined, null, 33, hexToBytes(PUBKEY)])("refuses %p", (value) => {
        expect(() => decodeBareHexBytes({ ...FIELD, value }, 33)).toThrow(FORM);
    });
});

describe("encodeBareHexBytes", () => {
    it("writes lowercase hex without a prefix, which the reader reads back", () => {
        const bytes = Uint8Array.of(0x02, 0xab, 0xcd);
        expect(encodeBareHexBytes("pubkey", bytes, 3)).toBe("02abcd");
        expect(decodeBareHexBytes({ ...FIELD, value: encodeBareHexBytes("pubkey", bytes, 3) }, 3)).toEqual(bytes);
    });

    it.each([2, 4])("refuses %i bytes where 3 are due, naming the value", (length) => {
        expect(() => encodeBareHexBytes("pubkey", new Uint8Array(length), 3)).toThrow(
            new TypeError(`pubkey must be 3 bytes, got ${length}`),
        );
    });

    it("refuses what is not bytes", () => {
        expect(() => encodeBareHexBytes("pubkey", "02abcd" as unknown as Uint8Array, 3)).toThrow(
            new TypeError("pubkey must be a Uint8Array"),
        );
    });
});

describe("assertWireHexBytes", () => {
    it("accepts wire hex of the exact length", () => {
        expect(() => assertWireHexBytes("channelId", `0x${"11".repeat(32)}`, 32)).not.toThrow();
    });

    it.each([
        ["no prefix", "11".repeat(32)],
        ["uppercase digits", `0x${"AA".repeat(32)}`],
        ["one byte short", `0x${"11".repeat(31)}`],
        ["one byte long", `0x${"11".repeat(33)}`],
        ["surrounding whitespace", ` 0x${"11".repeat(32)}`],
        ["a number", 1],
    ])("refuses %s, naming the value and not echoing it", (_, value) => {
        expect(() => assertWireHexBytes("channelId", value, 32)).toThrow(
            new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
        );
    });
});
