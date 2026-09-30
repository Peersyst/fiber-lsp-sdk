import { hexToBytes } from "@noble/hashes/utils.js";
import type { RpcPaymentHashParams } from "../../../../src/rpc";
import { encodeRpcPaymentHashParams } from "../../../../src/rpc";
import { toRpcPaymentHashParams } from "../../../utils/rpc-typed";
import { loadRpcVectors } from "../../../utils/rpc-vectors";

const vectors = loadRpcVectors();

const CASES = (["get_invoice", "cancel_invoice", "get_payment"] as const).flatMap((method) =>
    vectors.methods[method].params.map((entry) => [method, entry.name, entry] as const),
);

describe("encodeRpcPaymentHashParams", () => {
    it("writes the hash as 0x hex, and nothing else", () => {
        const wire = encodeRpcPaymentHashParams({ paymentHash: hexToBytes("3c".repeat(32)) });
        expect(wire).toEqual({ payment_hash: `0x${"3c".repeat(32)}` });
        expect(Object.keys(wire)).toEqual(["payment_hash"]);
    });

    it("writes only the hash of params that carry more", () => {
        const params = { paymentHash: new Uint8Array(32), paymentPreimage: new Uint8Array(32).fill(7) };
        expect(encodeRpcPaymentHashParams(params)).toEqual({ payment_hash: `0x${"00".repeat(32)}` });
    });

    it.each(CASES)("writes %s / %s as fiber's serde does", (_, __, entry) => {
        expect(encodeRpcPaymentHashParams(toRpcPaymentHashParams(entry.values))).toEqual(entry.json);
    });

    it.each<[string, unknown, Error]>([
        ["a hash of 31 bytes", new Uint8Array(31), new TypeError("paymentHash must be 32 bytes, got 31")],
        ["a hash of 33 bytes", new Uint8Array(33), new TypeError("paymentHash must be 32 bytes, got 33")],
        ["an empty hash", new Uint8Array(0), new TypeError("paymentHash must be 32 bytes, got 0")],
        ["a hash as 0x hex", `0x${"3c".repeat(32)}`, new TypeError("paymentHash must be a Uint8Array")],
        ["a hash as a plain array", Array.from({ length: 32 }, () => 0), new TypeError("paymentHash must be a Uint8Array")],
        ["a missing hash", undefined, new TypeError("paymentHash must be a Uint8Array")],
    ])("refuses %s", (_, paymentHash, expected) => {
        expect(() => encodeRpcPaymentHashParams({ paymentHash } as RpcPaymentHashParams)).toThrow(expected);
    });
});
