import { assertBytes, assertHexBytes, assertNonEmptyString, assertUnsignedInteger } from "../../../../src/common/utils/assert.utils";

describe("assertBytes", () => {
    it("accepts a byte array of the exact length", () => {
        expect(() => assertBytes("seed", new Uint8Array(32), 32)).not.toThrow();
    });

    it.each([0, 31, 33, 64])("rejects a length of %i bytes", (length) => {
        expect(() => assertBytes("seed", new Uint8Array(length), 32)).toThrow(new TypeError(`seed must be 32 bytes, got ${length}`));
    });

    it("rejects a value that is not a byte array", () => {
        const notBytes = "42".repeat(32) as unknown as Uint8Array;
        expect(() => assertBytes("seed", notBytes, 32)).toThrow(new TypeError("seed must be a Uint8Array"));
    });

    // A Node host passing a Buffer is passing a Uint8Array subclass, and the guard is
    // meant to catch miswiring, not to reject a valid byte array.
    it("accepts a Buffer", () => {
        expect(() => assertBytes("seed", Buffer.alloc(32), 32)).not.toThrow();
    });
});

describe("assertUnsignedInteger", () => {
    it.each([0, 1, 10])("accepts %i within the range", (value) => {
        expect(() => assertUnsignedInteger("index", value, 10)).not.toThrow();
    });

    it.each([-1, 11, 1.5, -0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1])("rejects %p", (value) => {
        expect(() => assertUnsignedInteger("index", value, 10)).toThrow(RangeError);
    });

    // The guards exist because the host may be untyped JavaScript, so a value that is
    // not a number at all has to be refused like any other out-of-range one.
    it("rejects a value that is not a number", () => {
        expect(() => assertUnsignedInteger("index", "5" as unknown as number, 10)).toThrow(RangeError);
    });

    it("names the offending value in the message", () => {
        expect(() => assertUnsignedInteger("commitmentNumber", -1, 10)).toThrow(
            new RangeError("commitmentNumber must be an integer between 0 and 10, got -1"),
        );
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
