import { UINT64_MAX, UINT128_MAX } from "../../../src/common";
import { WireError, decodeUintHex, decodeUintHexNumber, encodeUintHex } from "../../../src/wire";

const FIELD = { path: "root" };
const FORM = "root must be an unsigned integer in 0x hex without leading zeros";

describe("decodeUintHex", () => {
    it("reads fiber's hex form", () => {
        expect(decodeUintHex({ ...FIELD, value: "0x0" }, UINT128_MAX)).toBe(0n);
        expect(decodeUintHex({ ...FIELD, value: "0x1" }, UINT128_MAX)).toBe(1n);
        expect(decodeUintHex({ ...FIELD, value: "0xff" }, UINT128_MAX)).toBe(255n);
        expect(decodeUintHex({ ...FIELD, value: "0xa" }, UINT128_MAX)).toBe(10n);
        expect(decodeUintHex({ ...FIELD, value: `0x${"f".repeat(16)}` }, UINT64_MAX)).toBe(UINT64_MAX);
        expect(decodeUintHex({ ...FIELD, value: `0x${"f".repeat(32)}` }, UINT128_MAX)).toBe(UINT128_MAX);
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
        ["more digits than a u128 has", `0x1${"0".repeat(32)}`],
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
        expect(() => decodeUintHex({ ...FIELD, value: `0x1${"0".repeat(16)}` }, UINT64_MAX)).toThrow(`root must be at most ${UINT64_MAX}`);
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
        expect(encodeUintHex(0n, UINT128_MAX)).toBe("0x0");
        expect(encodeUintHex(1n, UINT128_MAX)).toBe("0x1");
        expect(encodeUintHex(10n, UINT128_MAX)).toBe("0xa");
        expect(encodeUintHex(255n, UINT128_MAX)).toBe("0xff");
        expect(encodeUintHex(256n, UINT128_MAX)).toBe("0x100");
        expect(encodeUintHex(UINT64_MAX, UINT64_MAX)).toBe(`0x${"f".repeat(16)}`);
        expect(encodeUintHex(UINT128_MAX, UINT128_MAX)).toBe(`0x${"f".repeat(32)}`);
    });

    it("writes what the reader reads back", () => {
        for (const value of [0n, 1n, 15n, 16n, 0xdeadbeefn, UINT64_MAX, UINT64_MAX + 1n, UINT128_MAX]) {
            expect(decodeUintHex({ ...FIELD, value: encodeUintHex(value, UINT128_MAX) }, UINT128_MAX)).toBe(value);
        }
    });

    it("holds the value to the bound", () => {
        expect(encodeUintHex(255n, 255n)).toBe("0xff");
        expect(() => encodeUintHex(256n, 255n)).toThrow(RangeError);
        expect(() => encodeUintHex(UINT64_MAX + 1n, UINT64_MAX)).toThrow(RangeError);
    });

    it("refuses a negative value", () => {
        expect(() => encodeUintHex(-1n, UINT128_MAX)).toThrow(RangeError);
    });

    it("refuses a number, which would lose precision past 2^53", () => {
        expect(() => encodeUintHex(1 as unknown as bigint, UINT128_MAX)).toThrow(RangeError);
    });
});
