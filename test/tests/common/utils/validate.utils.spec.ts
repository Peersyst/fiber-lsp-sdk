import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import {
    isCanonicalDecimal,
    isCompressedPoint,
    isDecimalShannons,
    isHexBytes,
    isNonEmptyHexBytes,
    isNonEmptyString,
    isPlainObject,
    isUnsignedInteger,
} from "../../../../src/common/utils/validate.utils";

describe("isPlainObject", () => {
    it.each([{}, { a: 1 }, Object.create(null) as object, new Date()])("accepts %p", (value) => {
        expect(isPlainObject(value)).toBe(true);
    });

    // The three shapes that pass a naive `typeof value === "object"` check and would
    // then be read field by field as if they were a record.
    it.each([null, [], [{ a: 1 }]])("rejects %p", (value) => {
        expect(isPlainObject(value)).toBe(false);
    });

    it.each(["", "text", 0, 42, true, undefined, 5n, Symbol("s"), () => undefined])("rejects the non-object %p", (value) => {
        expect(isPlainObject(value)).toBe(false);
    });
});

describe("isUnsignedInteger", () => {
    it.each([0, 1, 10])("accepts %i within the bound", (value) => {
        expect(isUnsignedInteger(value, 10)).toBe(true);
    });

    it.each([-1, 11, 1.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, "5", null, undefined, 5n])("rejects %p", (value) => {
        expect(isUnsignedInteger(value, 10)).toBe(false);
    });
});

describe("isHexBytes", () => {
    it("accepts lowercase hex of the exact size", () => {
        expect(isHexBytes("ab".repeat(32), 32)).toBe(true);
        expect(isHexBytes("0123456789abcdef", 8)).toBe(true);
    });

    it.each([
        ["uppercase hex", "AB".repeat(32)],
        ["a 0x prefix", "0x" + "ab".repeat(31)],
        ["one byte short", "ab".repeat(31)],
        ["one byte long", "ab".repeat(33)],
        ["an odd character", "g".repeat(64)],
        ["the empty string", ""],
    ])("rejects %s", (_, value) => {
        expect(isHexBytes(value, 32)).toBe(false);
    });

    it("rejects a non-string", () => {
        expect(isHexBytes(42, 32)).toBe(false);
    });
});

describe("isNonEmptyHexBytes", () => {
    it.each(["00", "ab".repeat(53), "0123456789abcdef"])("accepts %s", (value) => {
        expect(isNonEmptyHexBytes(value)).toBe(true);
    });

    it.each([
        ["the empty string", ""],
        ["half a byte", "abc"],
        ["uppercase hex", "AB"],
        ["a 0x prefix", "0xab"],
        ["an odd character", "gg"],
    ])("rejects %s", (_, value) => {
        expect(isNonEmptyHexBytes(value)).toBe(false);
    });

    it("rejects a non-string", () => {
        expect(isNonEmptyHexBytes(42)).toBe(false);
    });
});

describe("isCanonicalDecimal", () => {
    // Unbounded on purpose: the callers that have a cap apply their own.
    it.each(["0", "1", "10", "9007199254740993", "9".repeat(1000)])("accepts %s", (value) => {
        expect(isCanonicalDecimal(value)).toBe(true);
    });

    it.each(["", "00", "01", "-1", "+1", "1.5", "1e3", " 1", "1 ", "0x10", "١٢٣"])("rejects %p", (value) => {
        expect(isCanonicalDecimal(value)).toBe(false);
    });
});

describe("isNonEmptyString", () => {
    it.each(["a", "0", " ", "0x1f"])("accepts %p", (value) => {
        expect(isNonEmptyString(value)).toBe(true);
    });

    it.each(["", 42, null, undefined, [], {}, 5n])("rejects %p", (value) => {
        expect(isNonEmptyString(value)).toBe(false);
    });
});

describe("isDecimalShannons", () => {
    it.each(["0", "1", "10", "5000000000", "340282366920938463463374607431768211455"])("accepts %s", (value) => {
        expect(isDecimalShannons(value)).toBe(true);
    });

    it.each(["", "01", "-1", "+1", "1.5", "1e3", " 1", "1 ", "0x10", "١٢٣"])("rejects %p", (value) => {
        expect(isDecimalShannons(value)).toBe(false);
    });

    it("rejects amounts beyond u128", () => {
        expect(isDecimalShannons("340282366920938463463374607431768211455")).toBe(true);
        expect(isDecimalShannons("340282366920938463463374607431768211456")).toBe(false);
        expect(isDecimalShannons("1" + "0".repeat(39))).toBe(false);
        expect(isDecimalShannons("9".repeat(1000))).toBe(false);
    });

    it.each([5, 5n, null, undefined])("rejects the non-string %p", (value) => {
        expect(isDecimalShannons(value)).toBe(false);
    });
});

describe("isCompressedPoint", () => {
    const GENERATOR = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    it("accepts a point on the curve", () => {
        expect(isCompressedPoint(GENERATOR)).toBe(true);
    });

    it.each([
        ["the point in hex", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],
        ["the x alone", GENERATOR.subarray(1)],
        ["the point with a byte appended", Uint8Array.of(...GENERATOR, 0)],
        ["an uncompressed prefix", Uint8Array.of(0x04, ...GENERATOR.subarray(1))],
        ["the point uncompressed, 65 bytes that decode", secp256k1.Point.fromBytes(GENERATOR).toBytes(false)],
        ["an x off the curve", Uint8Array.of(0x02, ...new Uint8Array(32))],
        ["null", null],
    ])("refuses %s", (_, value) => {
        expect(isCompressedPoint(value)).toBe(false);
    });
});
