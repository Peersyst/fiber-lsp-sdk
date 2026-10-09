import { hexToBytes } from "@noble/hashes/utils.js";
import {
    assertAnyBytes,
    assertBoolean,
    assertBytes,
    assertCompressedPoint,
    assertDecimalShannons,
    assertFunction,
    assertHexBytes,
    assertNonEmptyString,
    assertOneOf,
    assertOutPoint,
    assertScript,
    assertScriptTemplate,
    assertString,
    assertTimerDelayMs,
    assertUnsignedBigInt,
    assertUnsignedInteger,
} from "../../../../src/common/utils/assert.utils";

describe("assertAnyBytes", () => {
    it.each([0, 1, 32, 85])("accepts a byte array of %i bytes", (length) => {
        expect(() => assertAnyBytes("witness", new Uint8Array(length))).not.toThrow();
    });

    it("accepts a Buffer", () => {
        expect(() => assertAnyBytes("witness", Buffer.alloc(3))).not.toThrow();
    });

    it.each([undefined, null, "0x55", 85, [0x55], new ArrayBuffer(1), new Uint16Array(1)])("rejects %p", (value) => {
        expect(() => assertAnyBytes("witness", value)).toThrow(new TypeError("witness must be a Uint8Array"));
    });
});

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

describe("assertUnsignedBigInt", () => {
    it.each([0n, 1n, 10n])("accepts %p within the range", (value) => {
        expect(() => assertUnsignedBigInt("amount", value, 10n)).not.toThrow();
    });

    it.each([-1n, 11n])("rejects %p", (value) => {
        expect(() => assertUnsignedBigInt("amount", value, 10n)).toThrow(RangeError);
    });

    it("rejects a value that is not a bigint", () => {
        expect(() => assertUnsignedBigInt("amount", 5 as unknown as bigint, 10n)).toThrow(RangeError);
        expect(() => assertUnsignedBigInt("amount", "5" as unknown as bigint, 10n)).toThrow(RangeError);
    });

    it("names the offending value in the message", () => {
        expect(() => assertUnsignedBigInt("amount", -1n, 10n)).toThrow(new RangeError("amount must be a bigint between 0 and 10, got -1"));
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

describe("assertBoolean", () => {
    it.each([true, false])("accepts %p", (value) => {
        expect(() => assertBoolean("public", value)).not.toThrow();
    });

    it.each(["true", "", 1, 0, null, undefined, [], {}, [true]])("rejects %p", (value) => {
        expect(() => assertBoolean("public", value)).toThrow(new TypeError("public must be a boolean"));
    });
});

describe("assertString", () => {
    it.each(["coffee", "", " ", "0"])("accepts %p", (value) => {
        expect(() => assertString("description", value)).not.toThrow();
    });

    it.each([undefined, null, 0, 5, true, [], ["coffee"], {}, new String("coffee")])("rejects %p", (value) => {
        expect(() => assertString("description", value)).toThrow(new TypeError("description must be a string"));
    });
});

describe("assertDecimalShannons", () => {
    it.each(["0", "62000000000"])("accepts %p", (value) => {
        expect(() => assertDecimalShannons("amountShannons", value)).not.toThrow();
    });

    it.each(["", "01", "0x10", "-1", 42 as unknown as string])("rejects %p", (value) => {
        expect(() => assertDecimalShannons("amountShannons", value)).toThrow(
            new TypeError("amountShannons must be an amount in decimal shannons"),
        );
    });
});

describe("assertOneOf", () => {
    const FILTERS = ["include_closed", "only_pending"] as const;

    it.each(FILTERS)("accepts %s", (value) => {
        expect(() => assertOneOf("filter", value, FILTERS)).not.toThrow();
    });

    it.each(["closed", "INCLUDE_CLOSED", " include_closed", "include_closed|only_pending", "", undefined, null, 1, ["include_closed"]])(
        "rejects %p, naming the value and listing the set",
        (value) => {
            expect(() => assertOneOf("filter", value, FILTERS)).toThrow(
                new TypeError("filter must be one of include_closed, only_pending"),
            );
        },
    );

    it("accepts nothing when the set is empty", () => {
        expect(() => assertOneOf("filter", "include_closed", [])).toThrow(new TypeError("filter must be one of "));
    });
});

describe("assertFunction", () => {
    it("accepts a function, an arrow or a class alike", () => {
        expect(() => assertFunction("now", () => 0)).not.toThrow();
        expect(() => assertFunction("now", Date.now)).not.toThrow();
        expect(() => assertFunction("now", class {})).not.toThrow();
    });

    it.each([undefined, null, 0, "Date.now", {}])("rejects %p, naming the field", (value) => {
        expect(() => assertFunction("now", value)).toThrow(new TypeError("now must be a function"));
    });
});

describe("assertCompressedPoint", () => {
    const GENERATOR = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    it("accepts a point on the curve, under either parity", () => {
        expect(() => assertCompressedPoint("key", GENERATOR)).not.toThrow();
        expect(() => assertCompressedPoint("key", Uint8Array.of(0x03, ...GENERATOR.subarray(1)))).not.toThrow();
    });

    it.each([
        ["a key in hex", "02" + "79".repeat(32), new TypeError("key must be a Uint8Array")],
        ["a key of 32 bytes", GENERATOR.subarray(1), new TypeError("key must be 33 bytes, got 32")],
        [
            "an uncompressed prefix",
            Uint8Array.of(0x04, ...GENERATOR.subarray(1)),
            new TypeError("key must be a compressed point on secp256k1"),
        ],
        ["33 zero bytes", new Uint8Array(33), new TypeError("key must be a compressed point on secp256k1")],
        ["an x off the curve", Uint8Array.of(0x02, ...new Uint8Array(32)), new TypeError("key must be a compressed point on secp256k1")],
    ])("rejects %s, naming the field", (_, value, error) => {
        expect(() => assertCompressedPoint("key", value)).toThrow(error);
    });
});

describe("assertScript", () => {
    const SCRIPT = { codeHash: new Uint8Array(32), hashType: "data2", args: new Uint8Array(0) };

    it("accepts a script with empty args, and with any length of them", () => {
        expect(() => assertScript("lock", SCRIPT)).not.toThrow();
        expect(() => assertScript("lock", { ...SCRIPT, args: new Uint8Array(1000) })).not.toThrow();
    });

    it.each([
        ["null", null, "lock must be an object"],
        ["an array", [], "lock must be an object"],
        ["a code hash of 31 bytes", { ...SCRIPT, codeHash: new Uint8Array(31) }, "lock.codeHash must be 32 bytes, got 31"],
        ["a code hash in hex", { ...SCRIPT, codeHash: "00".repeat(32) }, "lock.codeHash must be a Uint8Array"],
        ["an unknown hash type", { ...SCRIPT, hashType: "data3" }, "lock.hashType must be one of data, type, data1, data2"],
        ["no hash type", { codeHash: SCRIPT.codeHash, args: SCRIPT.args }, "lock.hashType must be one of data, type, data1, data2"],
        ["args in hex", { ...SCRIPT, args: "00" }, "lock.args must be a Uint8Array"],
    ])("rejects %s, naming the field", (_, value, message) => {
        expect(() => assertScript("lock", value)).toThrow(new TypeError(message));
    });
});

describe("assertScriptTemplate", () => {
    const TEMPLATE = { codeHash: new Uint8Array(32), hashType: "type" };

    it("accepts a template, with or without args beside it", () => {
        expect(() => assertScriptTemplate("commitmentLock", TEMPLATE)).not.toThrow();
        expect(() => assertScriptTemplate("commitmentLock", { ...TEMPLATE, args: new Uint8Array(20) })).not.toThrow();
    });

    it.each([
        ["null", null, "commitmentLock must be an object"],
        ["an array", [], "commitmentLock must be an object"],
        ["a string", "0x" + "00".repeat(32), "commitmentLock must be an object"],
        ["a code hash of 33 bytes", { ...TEMPLATE, codeHash: new Uint8Array(33) }, "commitmentLock.codeHash must be 32 bytes, got 33"],
        ["a code hash in hex", { ...TEMPLATE, codeHash: "00".repeat(32) }, "commitmentLock.codeHash must be a Uint8Array"],
        ["no code hash", { hashType: "type" }, "commitmentLock.codeHash must be a Uint8Array"],
        ["an unknown hash type", { ...TEMPLATE, hashType: "data3" }, "commitmentLock.hashType must be one of data, type, data1, data2"],
        ["no hash type", { codeHash: TEMPLATE.codeHash }, "commitmentLock.hashType must be one of data, type, data1, data2"],
    ])("rejects %s, naming the field", (_, value, message) => {
        expect(() => assertScriptTemplate("commitmentLock", value)).toThrow(new TypeError(message));
    });
});

describe("assertTimerDelayMs", () => {
    it.each([
        [0, 0],
        [1, 1],
        [1, 5_000],
        [1, 2 ** 31 - 1],
    ])("accepts, with a floor of %i, a delay of %i", (min, value) => {
        expect(() => assertTimerDelayMs("pollIntervalMs", value, min)).not.toThrow();
    });

    it.each([
        [1, 0],
        [0, -1],
        [1, 1.5],
        [1, NaN],
        [1, Infinity],
        [1, 2 ** 31],
        [1_000, 999],
    ])("rejects, with a floor of %i, a delay of %p", (min, value) => {
        expect(() => assertTimerDelayMs("pollIntervalMs", value, min)).toThrow(
            new RangeError(`pollIntervalMs must be an integer between ${min} and 2147483647, got ${value}`),
        );
    });

    it("rejects a value that is not a number", () => {
        expect(() => assertTimerDelayMs("pollIntervalMs", "5000" as unknown as number, 1)).toThrow(RangeError);
    });
});

describe("assertOutPoint", () => {
    const OUT_POINT = { txHash: new Uint8Array(32), index: 0 };

    it("accepts an out point at either end of the index's range", () => {
        expect(() => assertOutPoint("funding", OUT_POINT)).not.toThrow();
        expect(() => assertOutPoint("funding", { ...OUT_POINT, index: 2 ** 32 - 1 })).not.toThrow();
    });

    it.each([
        ["null", null, new TypeError("funding must be an object")],
        ["an array", [], new TypeError("funding must be an object")],
        ["a tx hash of 31 bytes", { ...OUT_POINT, txHash: new Uint8Array(31) }, new TypeError("funding.txHash must be 32 bytes, got 31")],
        ["a tx hash in hex", { ...OUT_POINT, txHash: "00".repeat(32) }, new TypeError("funding.txHash must be a Uint8Array")],
        [
            "a negative index",
            { ...OUT_POINT, index: -1 },
            new RangeError("funding.index must be an integer between 0 and 4294967295, got -1"),
        ],
        [
            "an index above u32",
            { ...OUT_POINT, index: 2 ** 32 },
            new RangeError("funding.index must be an integer between 0 and 4294967295, got 4294967296"),
        ],
        [
            "no index",
            { txHash: OUT_POINT.txHash },
            new RangeError("funding.index must be an integer between 0 and 4294967295, got undefined"),
        ],
    ])("rejects %s, naming the field", (_, value, error) => {
        expect(() => assertOutPoint("funding", value)).toThrow(error);
    });
});
