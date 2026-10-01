import { hexToBytes } from "@noble/hashes/utils.js";
import type { NewInvoiceParams, SettleInvoiceParams } from "../../../src/rpc";
import {
    FiberRpcClient,
    RPC_INVOICE_CURRENCIES,
    RPC_INVOICE_STATUSES,
    RpcError,
    RpcResponseError,
    decodeNewInvoiceResult,
    decodeRpcInvoice,
    decodeSettleInvoiceResult,
    encodeNewInvoiceParams,
    encodeSettleInvoiceParams,
} from "../../../src/rpc";
import { FetchMock } from "../../mocks/rpc";
import { caseOf } from "../../utils/interop-vectors";
import { refusal } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import { RPC_RESULT_PATH as RESULT, answering, refusing, resultField as result, sent } from "../../utils/rpc-answers";
import { toNewInvoiceParams, toNewInvoiceResult, toRpcInvoice, toSettleInvoiceParams, withoutNulls } from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { U64_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const { new_invoice: create, get_invoice: get, settle_invoice: settle, cancel_invoice: cancel } = vectors.methods;

const URL = "http://fiber.example:8227";
const PAYMENT_HASH = "3c".repeat(32);
const PREIMAGE = "e7".repeat(32);
const ADDRESS = "fibt2500000001pq5yk5a6mzq0vc3hqwpf6t8a";

const NEW_INVOICE: NewInvoiceParams = {
    amountShannons: "250000000",
    currency: "Fibt",
    paymentHash: hexToBytes(PAYMENT_HASH),
    hashAlgorithm: "ckb-hash",
    expirySeconds: 3600n,
    description: "coffee",
};

const SETTLE: SettleInvoiceParams = { paymentHash: hexToBytes(PAYMENT_HASH), paymentPreimage: hexToBytes(PREIMAGE) };

const CREATED = {
    invoice_address: ADDRESS,
    invoice: {
        currency: "Fibt",
        amount: "0xee6b280",
        signature: null,
        data: { timestamp: "0x191dd9dec00", payment_hash: `0x${PAYMENT_HASH}`, attrs: [{ expiry_time: "0xe10" }] },
    },
};

const RECEIVED = { ...CREATED, status: "Received" };

describe("new_invoice", () => {
    describe("encodeNewInvoiceParams", () => {
        it("writes the client's closed subset in fiber's forms, the hash and never a preimage", () => {
            const wire = encodeNewInvoiceParams(NEW_INVOICE);
            expect(wire).toEqual({
                amount: "0xee6b280",
                description: "coffee",
                currency: "Fibt",
                payment_hash: `0x${PAYMENT_HASH}`,
                expiry: "0xe10",
                hash_algorithm: "ckb_hash",
            });
            expect(Object.keys(wire)).toEqual(["amount", "description", "currency", "payment_hash", "expiry", "hash_algorithm"]);
        });

        it.each(create.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeNewInvoiceParams(toNewInvoiceParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it("sends no description member without one, rather than a null", () => {
            const without = { ...NEW_INVOICE };
            delete without.description;
            expect(Object.keys(encodeNewInvoiceParams(without))).toEqual([
                "amount",
                "currency",
                "payment_hash",
                "expiry",
                "hash_algorithm",
            ]);
            expect(Object.keys(encodeNewInvoiceParams({ ...NEW_INVOICE, description: undefined }))).not.toContain("description");
        });

        it("sends an empty description as one, which is not the same invoice as none", () => {
            expect(encodeNewInvoiceParams({ ...NEW_INVOICE, description: "" }).description).toBe("");
        });

        it("names the hash algorithm as fiber spells it", () => {
            expect(encodeNewInvoiceParams({ ...NEW_INVOICE, hashAlgorithm: "ckb-hash" }).hash_algorithm).toBe("ckb_hash");
            expect(encodeNewInvoiceParams({ ...NEW_INVOICE, hashAlgorithm: "sha256" }).hash_algorithm).toBe("sha256");
        });

        it.each(RPC_INVOICE_CURRENCIES)("writes the currency %s as it is", (currency) => {
            expect(encodeNewInvoiceParams({ ...NEW_INVOICE, currency }).currency).toBe(currency);
        });

        it("writes the bounds of the expiry, a u64 of seconds", () => {
            expect(encodeNewInvoiceParams({ ...NEW_INVOICE, expirySeconds: 0n }).expiry).toBe("0x0");
            expect(encodeNewInvoiceParams({ ...NEW_INVOICE, expirySeconds: 2n ** 64n - 1n }).expiry).toBe(U64_MAX_HEX);
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["a fractional amount", { amountShannons: "1.5" }, new TypeError("amountShannons must be an amount in decimal shannons")],
            [
                "an amount with a leading zero",
                { amountShannons: "0250" },
                new TypeError("amountShannons must be an amount in decimal shannons"),
            ],
            ["an amount in hex", { amountShannons: "0xee6b280" }, new TypeError("amountShannons must be an amount in decimal shannons")],
            [
                "an amount past a u128",
                { amountShannons: "340282366920938463463374607431768211456" },
                new TypeError("amountShannons must be an amount in decimal shannons"),
            ],
            ["an amount as a number", { amountShannons: 250000000 }, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["a missing amount", { amountShannons: undefined }, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["a lowercase currency", { currency: "fibt" }, new TypeError("currency must be one of Fibb, Fibt, Fibd")],
            ["a currency fiber does not have", { currency: "CKB" }, new TypeError("currency must be one of Fibb, Fibt, Fibd")],
            ["a missing currency", { currency: undefined }, new TypeError("currency must be one of Fibb, Fibt, Fibd")],
            ["a payment hash of 31 bytes", { paymentHash: new Uint8Array(31) }, new TypeError("paymentHash must be 32 bytes, got 31")],
            ["a payment hash of 33 bytes", { paymentHash: new Uint8Array(33) }, new TypeError("paymentHash must be 32 bytes, got 33")],
            ["a payment hash as hex", { paymentHash: `0x${PAYMENT_HASH}` }, new TypeError("paymentHash must be a Uint8Array")],
            ["a missing payment hash", { paymentHash: undefined }, new TypeError("paymentHash must be a Uint8Array")],
            [
                "the hash algorithm in fiber's spelling",
                { hashAlgorithm: "ckb_hash" },
                new TypeError("hashAlgorithm must be one of ckb-hash, sha256"),
            ],
            [
                "a hash algorithm fiber does not have",
                { hashAlgorithm: "blake2b" },
                new TypeError("hashAlgorithm must be one of ckb-hash, sha256"),
            ],
            [
                "a hash algorithm named after an object member",
                { hashAlgorithm: "constructor" },
                new TypeError("hashAlgorithm must be one of ckb-hash, sha256"),
            ],
            ["a missing hash algorithm", { hashAlgorithm: undefined }, new TypeError("hashAlgorithm must be one of ckb-hash, sha256")],
            [
                "an expiry as a number",
                { expirySeconds: 3600 },
                new RangeError("expirySeconds must be a bigint between 0 and 18446744073709551615, got 3600"),
            ],
            [
                "a negative expiry",
                { expirySeconds: -1n },
                new RangeError("expirySeconds must be a bigint between 0 and 18446744073709551615, got -1"),
            ],
            [
                "an expiry past a u64",
                { expirySeconds: 2n ** 64n },
                new RangeError("expirySeconds must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
            ],
            [
                "a missing expiry",
                { expirySeconds: undefined },
                new RangeError("expirySeconds must be a bigint between 0 and 18446744073709551615, got undefined"),
            ],
            ["a null description", { description: null }, new TypeError("description must be a string")],
            ["a description that is not a string", { description: 5 }, new TypeError("description must be a string")],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeNewInvoiceParams({ ...NEW_INVOICE, ...change } as NewInvoiceParams)).toThrow(expected);
        });

        it("has no way to send a preimage: a member of that name is not written", () => {
            const smuggled = { ...NEW_INVOICE, paymentPreimage: hexToBytes(PREIMAGE), payment_preimage: `0x${PREIMAGE}` };
            expect(JSON.stringify(encodeNewInvoiceParams(smuggled))).not.toContain(PREIMAGE);
        });
    });

    describe("decodeNewInvoiceResult", () => {
        it.each(create.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeNewInvoiceResult(result(entry.json))).toEqual(toNewInvoiceResult(entry.values));
        });

        it("reads the encoded invoice and nothing else", () => {
            expect(decodeNewInvoiceResult(result(CREATED))).toEqual({ invoiceAddress: ADDRESS });
        });

        it("ignores the parsed invoice, missing or malformed", () => {
            expect(decodeNewInvoiceResult(result({ invoice_address: ADDRESS }))).toEqual({ invoiceAddress: ADDRESS });
            expect(decodeNewInvoiceResult(result({ invoice_address: ADDRESS, invoice: "x", status: 5, extra: {} }))).toEqual({
                invoiceAddress: ADDRESS,
            });
        });

        it.each([undefined, null, "", 5, [ADDRESS]])("refuses invoice_address = %p", (value) => {
            expect(refusal(() => decodeNewInvoiceResult(result(withField(CREATED, "invoice_address", value)))).message).toBe(
                `${RESULT}.invoice_address must be a non-empty string`,
            );
        });

        it.each([null, [], ADDRESS])("refuses the result %p, which is not an object", (value) => {
            expect(refusal(() => decodeNewInvoiceResult(result(value))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("get_invoice and cancel_invoice", () => {
    describe("decodeRpcInvoice", () => {
        it.each([...get.results, ...cancel.results].map((entry) => [entry.name, entry] as const))("reads the %s invoice", (_, entry) => {
            expect(decodeRpcInvoice(result(entry.json))).toEqual(toRpcInvoice(entry.values));
        });

        it("reads the encoded invoice and the status", () => {
            expect(decodeRpcInvoice(result(RECEIVED))).toEqual({ invoiceAddress: ADDRESS, status: "Received" });
        });

        it.each(RPC_INVOICE_STATUSES)("reads the status %s", (status) => {
            expect(decodeRpcInvoice(result({ ...RECEIVED, status })).status).toBe(status);
        });

        it("ignores the parsed invoice, missing or malformed", () => {
            expect(decodeRpcInvoice(result({ invoice_address: ADDRESS, status: "Paid", invoice: 5, extra: [] }))).toEqual({
                invoiceAddress: ADDRESS,
                status: "Paid",
            });
        });

        it.each([
            ["status", undefined],
            ["status", null],
            ["status", "received"],
            ["status", "RECEIVED"],
            ["status", "Settled"],
            ["status", "Received "],
            ["status", 3],
            ["status", ["Received"]],
            ["invoice_address", undefined],
            ["invoice_address", ""],
            ["invoice_address", null],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeRpcInvoice(result(withField(RECEIVED, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it("lists the statuses fiber has in the refusal of another", () => {
            expect(refusal(() => decodeRpcInvoice(result({ ...RECEIVED, status: "Settled" }))).message).toBe(
                `${RESULT}.status must be one of Open, Cancelled, Expired, Received, Paid`,
            );
        });

        it.each([null, [], "Received"])("refuses the result %p, which is not an object", (value) => {
            expect(refusal(() => decodeRpcInvoice(result(value))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("settle_invoice", () => {
    describe("encodeSettleInvoiceParams", () => {
        it("writes the hash and the preimage, both 0x hex", () => {
            const wire = encodeSettleInvoiceParams(SETTLE);
            expect(wire).toEqual({ payment_hash: `0x${PAYMENT_HASH}`, payment_preimage: `0x${PREIMAGE}` });
            expect(Object.keys(wire)).toEqual(["payment_hash", "payment_preimage"]);
        });

        it.each(settle.params.map((entry) => [entry.name, entry] as const))("writes the case %s as fiber's serde does", (_, entry) => {
            expect(encodeSettleInvoiceParams(toSettleInvoiceParams(entry.values))).toEqual(entry.json);
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["a payment hash of 31 bytes", { paymentHash: new Uint8Array(31) }, new TypeError("paymentHash must be 32 bytes, got 31")],
            ["a payment hash as hex", { paymentHash: PAYMENT_HASH }, new TypeError("paymentHash must be a Uint8Array")],
            ["a preimage of 31 bytes", { paymentPreimage: new Uint8Array(31) }, new TypeError("paymentPreimage must be 32 bytes, got 31")],
            ["a preimage of 33 bytes", { paymentPreimage: new Uint8Array(33) }, new TypeError("paymentPreimage must be 32 bytes, got 33")],
            ["a preimage as hex", { paymentPreimage: `0x${PREIMAGE}` }, new TypeError("paymentPreimage must be a Uint8Array")],
            ["a missing preimage", { paymentPreimage: undefined }, new TypeError("paymentPreimage must be a Uint8Array")],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeSettleInvoiceParams({ ...SETTLE, ...change } as SettleInvoiceParams)).toThrow(expected);
        });

        it.each<[string, unknown]>([
            ["of the wrong length", hexToBytes("e7".repeat(33))],
            ["given as hex", `0x${PREIMAGE}`],
            ["given as bare hex", PREIMAGE],
        ])("never echoes a preimage %s in its refusal", (_, paymentPreimage) => {
            let message = "";
            try {
                encodeSettleInvoiceParams({ ...SETTLE, paymentPreimage } as SettleInvoiceParams);
            } catch (error) {
                message = (error as Error).message;
            }
            expect(message).toMatch(/^paymentPreimage must be /);
            expect(message).not.toContain("e7");
        });
    });

    describe("decodeSettleInvoiceResult", () => {
        it.each(settle.results.map((entry) => [entry.name, entry] as const))("reads the %s empty object", (_, entry) => {
            expect(entry.json).toEqual({});
            expect(decodeSettleInvoiceResult(result(entry.json))).toBeUndefined();
        });

        it("ignores members a later fiber might add", () => {
            expect(decodeSettleInvoiceResult(result({ settled_at: "0x1" }))).toBeUndefined();
        });

        it.each([null, undefined, [], "ok", true, 0])("refuses %p", (value) => {
            expect(refusal(() => decodeSettleInvoiceResult(result(value))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("FiberRpcClient invoice methods", () => {
    const HASH_PARAMS = { payment_hash: `0x${PAYMENT_HASH}` };

    function clientOf(mock: FetchMock): FiberRpcClient {
        return new FiberRpcClient({ url: URL, fetch: mock.fetch });
    }

    it("creates a hold invoice and reads its encoded form", async () => {
        const mock = answering(CREATED);
        await expect(clientOf(mock).newInvoice(NEW_INVOICE)).resolves.toEqual({ invoiceAddress: ADDRESS });
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "new_invoice", params: [encodeNewInvoiceParams(NEW_INVOICE)] });
    });

    it("reads an invoice by its payment hash", async () => {
        const entry = caseOf(get.results, "received, largest amount");
        const mock = answering(entry.json);
        await expect(clientOf(mock).getInvoice({ paymentHash: hexToBytes(PAYMENT_HASH) })).resolves.toEqual(toRpcInvoice(entry.values));
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "get_invoice", params: [HASH_PARAMS] });
    });

    it("settles an invoice with its preimage, resolving with nothing", async () => {
        const mock = answering({});
        await expect(clientOf(mock).settleInvoice(SETTLE)).resolves.toBeUndefined();
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "settle_invoice",
            params: [{ payment_hash: `0x${PAYMENT_HASH}`, payment_preimage: `0x${PREIMAGE}` }],
        });
    });

    it("cancels an invoice and reads it back cancelled", async () => {
        const entry = caseOf(cancel.results, "cancelled");
        const mock = answering(entry.json);
        await expect(clientOf(mock).cancelInvoice({ paymentHash: hexToBytes(PAYMENT_HASH) })).resolves.toEqual({
            invoiceAddress: entry.values.invoice_address,
            status: "Cancelled",
        });
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "cancel_invoice", params: [HASH_PARAMS] });
    });

    it.each<[string, (client: FiberRpcClient) => Promise<unknown>]>([
        ["newInvoice", (client) => client.newInvoice({ ...NEW_INVOICE, paymentHash: new Uint8Array(31) })],
        ["getInvoice", (client) => client.getInvoice({ paymentHash: new Uint8Array(31) })],
        ["settleInvoice", (client) => client.settleInvoice({ ...SETTLE, paymentPreimage: new Uint8Array(31) })],
        ["cancelInvoice", (client) => client.cancelInvoice({ paymentHash: new Uint8Array(33) })],
    ])("%s refuses params it cannot write before sending anything", async (_, run) => {
        const mock = new FetchMock();
        await expect(run(clientOf(mock))).rejects.toThrow(TypeError);
        expect(mock.requests).toHaveLength(0);
    });

    it("passes the node's refusal through", async () => {
        const mock = refusing(-32000, "invoice not found");
        const error = await rejection(clientOf(mock).getInvoice({ paymentHash: hexToBytes(PAYMENT_HASH) }));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "get_invoice", code: -32000, message: "invoice not found" });
    });

    it("names the field of an answer it cannot read", async () => {
        const mock = answering({ ...RECEIVED, status: "Settled" });
        const error = await rejection(clientOf(mock).cancelInvoice({ paymentHash: hexToBytes(PAYMENT_HASH) }));
        expect(error).toBeInstanceOf(RpcResponseError);
        expect(error).toMatchObject({ method: "cancel_invoice", path: "response.result.status" });
    });

    it("does not take a null answer to a settle for a settled invoice", async () => {
        const error = await rejection(clientOf(answering(null)).settleInvoice(SETTLE));
        expect(error).toBeInstanceOf(RpcResponseError);
        expect(error).toMatchObject({ method: "settle_invoice", path: "response.result" });
    });
});
