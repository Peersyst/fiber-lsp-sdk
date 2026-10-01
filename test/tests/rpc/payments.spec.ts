import { hexToBytes } from "@noble/hashes/utils.js";
import type { SendPaymentParams } from "../../../src/rpc";
import {
    FiberRpcClient,
    RPC_PAYMENT_STATUSES,
    RpcError,
    RpcResponseError,
    decodeRpcPayment,
    encodeSendPaymentParams,
} from "../../../src/rpc";
import { FetchMock } from "../../mocks/rpc";
import { caseOf } from "../../utils/interop-vectors";
import { refusal } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import { RPC_RESULT_PATH as RESULT, answering, refusing, resultField as result, sent } from "../../utils/rpc-answers";
import { toRpcPayment, toSendPaymentParams, withoutNulls } from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { ABOVE_U64, ABOVE_U128, U64_MAX_HEX, U128_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const { send_payment: send, get_payment: get } = vectors.methods;

const URL = "http://fiber.example:8227";
const PAYMENT_HASH = "5a".repeat(32);
const INVOICE = "fibt2500000001pq5yk5a6mzq0vc3hqwpf6t8a";

const SEND: SendPaymentParams = { invoice: INVOICE, maxFeeAmountShannons: "1250000", dryRun: false };

const INFLIGHT = {
    payment_hash: `0x${PAYMENT_HASH}`,
    status: "Inflight",
    created_at: "0x191dd9dec00",
    last_updated_at: "0x191dd9defe8",
    failed_error: null,
    fee: "0x3039",
    custom_records: { "0x1": "0x01020304" },
};

const FAILED = { ...INFLIGHT, status: "Failed", failed_error: "Failed to build route, PathFind error: no path found", fee: "0x0" };

describe("send_payment", () => {
    describe("encodeSendPaymentParams", () => {
        it("writes the invoice, the fee bound in hex and the dry run, leaving every other option to the node", () => {
            const wire = encodeSendPaymentParams(SEND);
            expect(wire).toEqual({ invoice: INVOICE, max_fee_amount: "0x1312d0", dry_run: false });
            expect(Object.keys(wire)).toEqual(["invoice", "max_fee_amount", "dry_run"]);
        });

        it.each(send.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeSendPaymentParams(toSendPaymentParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it("always sends dry_run, false included, rather than inheriting fiber's default", () => {
            expect(encodeSendPaymentParams({ ...SEND, dryRun: false }).dry_run).toBe(false);
            expect(encodeSendPaymentParams({ ...SEND, dryRun: true }).dry_run).toBe(true);
        });

        it("writes the bounds of the fee", () => {
            expect(encodeSendPaymentParams({ ...SEND, maxFeeAmountShannons: "0" }).max_fee_amount).toBe("0x0");
            expect(
                encodeSendPaymentParams({ ...SEND, maxFeeAmountShannons: "340282366920938463463374607431768211455" }).max_fee_amount,
            ).toBe(U128_MAX_HEX);
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["an empty invoice", { invoice: "" }, new TypeError("invoice must be a non-empty string")],
            ["an invoice that is not a string", { invoice: 5 }, new TypeError("invoice must be a non-empty string")],
            ["a missing invoice", { invoice: undefined }, new TypeError("invoice must be a non-empty string")],
            [
                "a fractional fee bound",
                { maxFeeAmountShannons: "0.5" },
                new TypeError("maxFeeAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "a fee bound with a leading zero",
                { maxFeeAmountShannons: "01" },
                new TypeError("maxFeeAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "a fee bound in hex",
                { maxFeeAmountShannons: "0x1312d0" },
                new TypeError("maxFeeAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "a fee bound past a u128",
                { maxFeeAmountShannons: "340282366920938463463374607431768211456" },
                new TypeError("maxFeeAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "a fee bound as a number",
                { maxFeeAmountShannons: 1250000 },
                new TypeError("maxFeeAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "a missing fee bound",
                { maxFeeAmountShannons: undefined },
                new TypeError("maxFeeAmountShannons must be an amount in decimal shannons"),
            ],
            ["a dry run as a string", { dryRun: "false" }, new TypeError("dryRun must be a boolean")],
            ["a missing dry run", { dryRun: undefined }, new TypeError("dryRun must be a boolean")],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeSendPaymentParams({ ...SEND, ...change } as SendPaymentParams)).toThrow(expected);
        });
    });
});

describe("decodeRpcPayment", () => {
    it.each([...send.results, ...get.results].map((entry) => [entry.name, entry] as const))("reads the payment %s", (_, entry) => {
        expect(decodeRpcPayment(result(entry.json))).toEqual(toRpcPayment(entry.values));
    });

    it("reads a literal payment field by field", () => {
        expect(decodeRpcPayment(result(INFLIGHT))).toEqual({
            paymentHash: hexToBytes(PAYMENT_HASH),
            status: "Inflight",
            createdAtMs: 1726000000000n,
            lastUpdatedAtMs: 1726000001000n,
            failedError: null,
            feeShannons: "12345",
        });
    });

    it("reads a failure's message verbatim", () => {
        expect(decodeRpcPayment(result(FAILED))).toMatchObject({
            status: "Failed",
            failedError: "Failed to build route, PathFind error: no path found",
            feeShannons: "0",
        });
    });

    it.each(RPC_PAYMENT_STATUSES)("reads the status %s, with or without an error beside it", (status) => {
        expect(decodeRpcPayment(result({ ...INFLIGHT, status })).status).toBe(status);
        expect(decodeRpcPayment(result({ ...INFLIGHT, status, failed_error: "" }))).toMatchObject({ status, failedError: "" });
    });

    it("reads the largest fee and timestamps", () => {
        const payment = decodeRpcPayment(result({ ...INFLIGHT, created_at: U64_MAX_HEX, last_updated_at: U64_MAX_HEX, fee: U128_MAX_HEX }));
        expect(payment.createdAtMs).toBe(2n ** 64n - 1n);
        expect(payment.lastUpdatedAtMs).toBe(2n ** 64n - 1n);
        expect(payment.feeShannons).toBe("340282366920938463463374607431768211455");
    });

    it("ignores the members it does not read, missing or malformed", () => {
        const expected = decodeRpcPayment(result(INFLIGHT));
        expect(decodeRpcPayment(result(withField(INFLIGHT, "custom_records", undefined)))).toEqual(expected);
        expect(decodeRpcPayment(result({ ...INFLIGHT, custom_records: "x", routers: 5, extra: {} }))).toEqual(expected);
    });

    it.each([
        ["payment_hash", PAYMENT_HASH],
        ["payment_hash", `0x${"5a".repeat(31)}`],
        ["payment_hash", `0x${"5A".repeat(32)}`],
        ["payment_hash", undefined],
        ["payment_hash", null],
        ["status", "inflight"],
        ["status", "Pending"],
        ["status", "Inflight "],
        ["status", undefined],
        ["status", null],
        ["status", 1],
        ["created_at", "1726000000000"],
        ["created_at", "0x0191dd9dec00"],
        ["created_at", ABOVE_U64],
        ["created_at", 1726000000000],
        ["created_at", undefined],
        ["last_updated_at", "1726000001000"],
        ["last_updated_at", ABOVE_U64],
        ["last_updated_at", null],
        ["last_updated_at", undefined],
        ["failed_error", undefined],
        ["failed_error", 1],
        ["failed_error", ["no path found"]],
        ["fee", "12345"],
        ["fee", "0x03039"],
        ["fee", ABOVE_U128],
        ["fee", 12345],
        ["fee", undefined],
    ])("refuses %s = %p, naming the field from the result", (path, value) => {
        expect(refusal(() => decodeRpcPayment(result(withField(INFLIGHT, path, value)))).path).toBe(`${RESULT}.${path}`);
    });

    it("lists the statuses fiber has in the refusal of another", () => {
        expect(refusal(() => decodeRpcPayment(result({ ...INFLIGHT, status: "Pending" }))).message).toBe(
            `${RESULT}.status must be one of Created, Inflight, Success, Failed`,
        );
    });

    it.each([null, [], "Inflight"])("refuses the result %p, which is not an object", (value) => {
        expect(refusal(() => decodeRpcPayment(result(value))).message).toBe(`${RESULT} must be an object`);
    });
});

describe("FiberRpcClient payment methods", () => {
    function clientOf(mock: FetchMock): FiberRpcClient {
        return new FiberRpcClient({ url: URL, fetch: mock.fetch });
    }

    it("sends a payment and reads it as it stands", async () => {
        const entry = caseOf(send.results, "created");
        const mock = answering(entry.json);
        await expect(clientOf(mock).sendPayment(SEND)).resolves.toEqual(toRpcPayment(entry.values));
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "send_payment",
            params: [{ invoice: INVOICE, max_fee_amount: "0x1312d0", dry_run: false }],
        });
    });

    it("asks for a dry run with the same method", async () => {
        const mock = answering(INFLIGHT);
        await clientOf(mock).sendPayment({ ...SEND, dryRun: true });
        expect(sent(mock)).toMatchObject({ method: "send_payment", params: [{ dry_run: true }] });
    });

    it("reads a payment by its hash", async () => {
        const entry = caseOf(get.results, "success with a custom record");
        const mock = answering(entry.json);
        await expect(clientOf(mock).getPayment({ paymentHash: hexToBytes(PAYMENT_HASH) })).resolves.toEqual(toRpcPayment(entry.values));
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "get_payment", params: [{ payment_hash: `0x${PAYMENT_HASH}` }] });
    });

    it.each<[string, (client: FiberRpcClient) => Promise<unknown>]>([
        ["sendPayment", (client) => client.sendPayment({ ...SEND, invoice: "" })],
        ["getPayment", (client) => client.getPayment({ paymentHash: new Uint8Array(31) })],
    ])("%s refuses params it cannot write before sending anything", async (_, run) => {
        const mock = new FetchMock();
        await expect(run(clientOf(mock))).rejects.toThrow(TypeError);
        expect(mock.requests).toHaveLength(0);
    });

    it("passes the node's refusal through, its message verbatim", async () => {
        const mock = refusing(-32000, "Send payment error: invoice is expired");
        const error = await rejection(clientOf(mock).sendPayment(SEND));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "send_payment", code: -32000, message: "Send payment error: invoice is expired" });
    });

    it("names the field of an answer it cannot read", async () => {
        const mock = answering({ ...INFLIGHT, fee: "12345" });
        const error = await rejection(clientOf(mock).getPayment({ paymentHash: hexToBytes(PAYMENT_HASH) }));
        expect(error).toBeInstanceOf(RpcResponseError);
        expect(error).toMatchObject({ method: "get_payment", path: "response.result.fee" });
    });
});
