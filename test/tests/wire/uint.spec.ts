import { UINT64_MAX, UINT128_MAX } from "../../../src/common";
import { WireError, decodeUintHex, decodeUintHexNumber, encodeUintHex, encodeUintHexNumber } from "../../../src/wire";
import { ABOVE_U64, ABOVE_U128, U64_MAX_HEX, U128_MAX_HEX } from "../../utils/uint-hex";

const FIELD = { path: "root" };
const FORM = "root must be an unsigned integer in 0x hex without leading zeros";

describe("decodeUintHex", () => {
    it("reads fiber's hex form", () => {
        expect(decodeUintHex({ ...FIELD, value: "0x0" }, UINT128_MAX)).toBe(0n);
        expect(decodeUintHex({ ...FIELD, value: "0x1" }, UINT128_MAX)).toBe(1n);
        expect(decodeUintHex({ ...FIELD, value: "0xff" }, UINT128_MAX)).toBe(255n);
        expect(decodeUintHex({ ...FIELD, value: "0xa" }, UINT128_MAX)).toBe(10n);
        expect(decodeUintHex({ ...FIELD, value: U64_MAX_HEX }, UINT64_MAX)).toBe(UINT64_MAX);
        expect(decodeUintHex({ ...FIELD, value: U128_MAX_HEX }, UINT128_MAX)).toBe(UINT128_MAX);
    });

    it.each([
        ["a redundant leading zero", "0x00"],
        ["a leading zero before digits", "0x01"],
        ["no digits", "0x"],
        ["no prefix", "ff"],
        ["a decimal string", "255"],
        ["uppercase digits", "0xFF"],
        ["an uppercase prefix", "0XFF"],
        ["a sign", "0x-1"],
        ["leading whitespace", " 0x1"],
        ["trailing whitespace", "0x1 "],
        ["a non-hex digit", "0x1g"],
        ["more digits than a u128 has", ABOVE_U128],
    ])("refuses %s as a form error", (_, value) => {
        expect(() => decodeUintHex({ ...FIELD, value }, UINT128_MAX)).toThrow(WireError);
        expect(() => decodeUintHex({ ...FIELD, value }, UINT128_MAX)).toThrow(FORM);
    });

    it.each([255, 0, null, undefined, true, ["0x1"]])("refuses %p", (value) => {
        expect(() => decodeUintHex({ ...FIELD, value }, UINT128_MAX)).toThrow(FORM);
    });

    it("holds the value to the bound, naming the bound and not the value", () => {
        expect(decodeUintHex({ ...FIELD, value: "0xff" }, 255n)).toBe(255n);
        expect(() => decodeUintHex({ ...FIELD, value: "0x100" }, 255n)).toThrow("root must be at most 255");
        expect(() => decodeUintHex({ ...FIELD, value: ABOVE_U64 }, UINT64_MAX)).toThrow(`root must be at most ${UINT64_MAX}`);
    });

    it("never converts more digits than the widest wire integer has", () => {
        expect(() => decodeUintHex({ ...FIELD, value: `0x1${"0".repeat(1_000_000)}` }, UINT128_MAX)).toThrow(FORM);
    });
});

describe("decodeUintHexNumber", () => {
    it("reads the form into a safe integer", () => {
        expect(decodeUintHexNumber({ ...FIELD, value: "0x0" }, 255)).toBe(0);
        expect(decodeUintHexNumber({ ...FIELD, value: "0xff" }, 255)).toBe(255);
        expect(decodeUintHexNumber({ ...FIELD, value: "0x1fffffffffffff" }, Number.MAX_SAFE_INTEGER)).toBe(Number.MAX_SAFE_INTEGER);
    });

    it("holds the value to the bound", () => {
        expect(() => decodeUintHexNumber({ ...FIELD, value: "0x100" }, 255)).toThrow("root must be at most 255");
        expect(() => decodeUintHexNumber({ ...FIELD, value: "0x20000000000000" }, Number.MAX_SAFE_INTEGER)).toThrow(
            `root must be at most ${Number.MAX_SAFE_INTEGER}`,
        );
    });

    it("refuses the form errors the bigint reader refuses", () => {
        expect(() => decodeUintHexNumber({ ...FIELD, value: "0x01" }, 255)).toThrow(FORM);
        expect(() => decodeUintHexNumber({ ...FIELD, value: 1 }, 255)).toThrow(FORM);
    });

    it("rejects a bound a number cannot hold, which is a caller error and not a wire refusal", () => {
        expect(() => decodeUintHexNumber({ ...FIELD, value: "0x1" }, 2 ** 53)).toThrow(RangeError);
    });
});

describe("encodeUintHex", () => {
    it("writes fiber's hex form", () => {
        expect(encodeUintHex("fee", 0n, UINT128_MAX)).toBe("0x0");
        expect(encodeUintHex("fee", 1n, UINT128_MAX)).toBe("0x1");
        expect(encodeUintHex("fee", 10n, UINT128_MAX)).toBe("0xa");
        expect(encodeUintHex("fee", 255n, UINT128_MAX)).toBe("0xff");
        expect(encodeUintHex("fee", 256n, UINT128_MAX)).toBe("0x100");
        expect(encodeUintHex("fee", UINT64_MAX, UINT64_MAX)).toBe(U64_MAX_HEX);
        expect(encodeUintHex("fee", UINT128_MAX, UINT128_MAX)).toBe(U128_MAX_HEX);
    });

    it("writes what the reader reads back", () => {
        for (const value of [0n, 1n, 15n, 16n, 0xdeadbeefn, UINT64_MAX, UINT64_MAX + 1n, UINT128_MAX]) {
            expect(decodeUintHex({ ...FIELD, value: encodeUintHex("fee", value, UINT128_MAX) }, UINT128_MAX)).toBe(value);
        }
    });

    it("holds the value to the bound", () => {
        expect(encodeUintHex("fee", 255n, 255n)).toBe("0xff");
        expect(() => encodeUintHex("fee", 256n, 255n)).toThrow(new RangeError("fee must be a bigint between 0 and 255, got 256"));
        expect(() => encodeUintHex("fee", UINT64_MAX + 1n, UINT64_MAX)).toThrow(RangeError);
    });

    it("refuses a negative value", () => {
        expect(() => encodeUintHex("fee", -1n, UINT128_MAX)).toThrow(RangeError);
    });

    it("refuses a number, which would lose precision past 2^53", () => {
        expect(() => encodeUintHex("fee", 1 as unknown as bigint, UINT128_MAX)).toThrow(RangeError);
    });
});

describe("encodeUintHexNumber", () => {
    it("writes fiber's hex form up to the bound", () => {
        expect(encodeUintHexNumber("index", 0, 2 ** 32 - 1)).toBe("0x0");
        expect(encodeUintHexNumber("index", 255, 2 ** 32 - 1)).toBe("0xff");
        expect(encodeUintHexNumber("index", 2 ** 32 - 1, 2 ** 32 - 1)).toBe("0xffffffff");
        expect(encodeUintHexNumber("index", Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)).toBe("0x1fffffffffffff");
    });

    it("writes what the reader reads back", () => {
        for (const value of [0, 1, 16, 2 ** 32 - 1]) {
            expect(decodeUintHexNumber({ ...FIELD, value: encodeUintHexNumber("index", value, 2 ** 32 - 1) }, 2 ** 32 - 1)).toBe(value);
        }
    });

    it.each([
        ["past the bound", 2 ** 32],
        ["negative", -1],
        ["fractional", 1.5],
        ["NaN", NaN],
        ["a string", "1" as unknown as number],
        ["a bigint", 1n as unknown as number],
    ])("refuses a value %s", (_, value) => {
        expect(() => encodeUintHexNumber("index", value, 2 ** 32 - 1)).toThrow(RangeError);
    });

    it("names the value it refuses", () => {
        expect(() => encodeUintHexNumber("index", 2 ** 32, 2 ** 32 - 1)).toThrow(
            new RangeError("index must be an integer between 0 and 4294967295, got 4294967296"),
        );
    });
});
