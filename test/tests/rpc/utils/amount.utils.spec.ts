import { UINT128_MAX } from "../../../../src/common";
import { decodeShannons, encodeShannons } from "../../../../src/rpc";
import { WireError } from "../../../../src/wire";
import { loadRpcVectors } from "../../../utils/rpc-vectors";

const vectors = loadRpcVectors();

const AMOUNTS: [string, string, unknown][] = [
    ...vectors.methods.new_invoice.params.map((entry): [string, string, unknown] => [
        `new_invoice ${entry.name}`,
        entry.values.amount,
        (entry.json as { amount: unknown }).amount,
    ]),
    ...vectors.methods.send_payment.params.map((entry): [string, string, unknown] => [
        `send_payment ${entry.name}`,
        entry.values.max_fee_amount,
        (entry.json as { max_fee_amount: unknown }).max_fee_amount,
    ]),
];

describe("encodeShannons", () => {
    it("covers the largest amount among the vectors", () => {
        expect(AMOUNTS.map(([, shannons]) => shannons)).toContain(UINT128_MAX.toString());
    });

    it.each(AMOUNTS)("writes %s as fiber does", (_, shannons, wire) => {
        expect(encodeShannons("amount", shannons)).toBe(wire);
    });

    it("writes the bounds", () => {
        expect(encodeShannons("amount", "0")).toBe("0x0");
        expect(encodeShannons("amount", "340282366920938463463374607431768211455")).toBe(`0x${"f".repeat(32)}`);
    });

    it.each([
        ["an empty string", ""],
        ["a leading zero", "01"],
        ["a sign", "-1"],
        ["a plus sign", "+1"],
        ["a fraction", "1.0"],
        ["an exponent", "1e3"],
        ["whitespace", " 1"],
        ["hex", "0x1"],
        ["one past a u128", "340282366920938463463374607431768211456"],
    ])("refuses %s, naming the amount and not its value", (_, shannons) => {
        expect(() => encodeShannons("max_fee_amount", shannons)).toThrow(
            new TypeError("max_fee_amount must be an amount in decimal shannons"),
        );
    });

    it("refuses a number", () => {
        expect(() => encodeShannons("amount", 1 as unknown as string)).toThrow(TypeError);
    });
});

describe("decodeShannons", () => {
    it.each(AMOUNTS)("reads %s back to the SDK's form", (_, shannons, wire) => {
        expect(decodeShannons({ value: wire, path: "result.amount" })).toBe(shannons);
    });

    it("reads the bounds", () => {
        expect(decodeShannons({ value: "0x0", path: "result.amount" })).toBe("0");
        expect(decodeShannons({ value: `0x${"f".repeat(32)}`, path: "result.amount" })).toBe(UINT128_MAX.toString());
    });

    it.each([
        ["a decimal string", "100"],
        ["a leading zero", "0x01"],
        ["a JSON number", 100],
        ["more digits than a u128 has", `0x1${"0".repeat(32)}`],
    ])("refuses %s as a wire refusal of the field", (_, value) => {
        expect(() => decodeShannons({ value, path: "result.amount" })).toThrow(WireError);
        expect(() => decodeShannons({ value, path: "result.amount" })).toThrow(/^result\.amount /);
    });
});
