import { assertHexBytes, assertNonEmptyString, isHexBytes, isUnsignedInteger } from "../../../../src/common/utils/validate.utils";

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

describe("assertHexBytes", () => {
    it("accepts a valid value", () => {
        expect(() => assertHexBytes("digest", "ab".repeat(32), 32)).not.toThrow();
    });

    it("names the argument and size in the refusal", () => {
        expect(() => assertHexBytes("preimageHex", "nope", 32)).toThrow(new TypeError("preimageHex must be 32 bytes of lowercase hex"));
    });
});

describe("assertNonEmptyString", () => {
    it("accepts a non-empty string", () => {
        expect(() => assertNonEmptyString("channelId", "abc")).not.toThrow();
    });

    it.each(["", 42 as unknown as string, null as unknown as string, undefined as unknown as string])("rejects %p", (value) => {
        expect(() => assertNonEmptyString("channelId", value)).toThrow(new TypeError("channelId must be a non-empty string"));
    });
});
