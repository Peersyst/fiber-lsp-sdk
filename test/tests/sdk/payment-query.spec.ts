import { FiberRpcClient, RpcError, RpcTransportError } from "../../../src/rpc";
import { SignerStore } from "../../../src/policy";
import type { SdkPaymentQueryContext, SdkPaymentRecord, StoredPaymentRecord } from "../../../src/sdk";
import { PaymentHistory, getSdkPayment, listSdkPayments, readSdkPayment } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import { ScriptedNode } from "../../mocks/rpc";
import { getPaymentCall } from "../../utils/payment-calls";
import { rejection } from "../../utils/rejection";

const URL = "http://127.0.0.1:8227";
const HASH = "5a".repeat(32);
const OTHER_HASH = "7e".repeat(32);
const THIRD_HASH = "9c".repeat(32);
const NOT_FOUND = `InvalidParameter: Payment session not found: Hash256(0x${HASH})`;
const FIBER_REASON = "Send payment error: Failed to build route, PathFind error: no path found";
const CREATED_AT_MS = 1_791_367_200_000;

const SEND: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH}`,
    direction: "send",
    status: "completed",
    amountShannons: "250000000",
    invoice: "fibt2500000001send",
    description: "coffee",
    maxFeeShannons: "1250000",
    feeShannons: "1000",
    failedReason: null,
    createdAtMs: CREATED_AT_MS,
    settledAtMs: CREATED_AT_MS + 4000,
};

const SEND_READ: SdkPaymentRecord = {
    paymentHashHex: `0x${HASH}`,
    direction: "send",
    status: "completed",
    amountShannons: "250000000",
    invoice: "fibt2500000001send",
    description: "coffee",
    maxFeeShannons: "1250000",
    feeShannons: "1000",
    failedReason: null,
    createdAtMs: CREATED_AT_MS,
    settledAtMs: CREATED_AT_MS + 4000,
};

function receiveAt(paymentHash: string, createdAtMs: number): StoredPaymentRecord {
    return {
        version: 1,
        paymentHashHex: `0x${paymentHash}`,
        direction: "receive",
        status: "pending",
        amountShannons: "100000000",
        invoice: "fibt1000000001receive",
        description: null,
        maxFeeShannons: null,
        feeShannons: null,
        failedReason: null,
        createdAtMs,
        settledAtMs: null,
    };
}

type Harness = { storage: InMemorySignerStorage; history: PaymentHistory; context: SdkPaymentQueryContext };

function harness(): Harness {
    const storage = new InMemorySignerStorage();
    const history = new PaymentHistory(new SignerStore(storage));
    return { storage, history, context: { history } };
}

async function seed(h: Harness, record: StoredPaymentRecord): Promise<void> {
    await h.history.update(record.paymentHashHex.slice(2), () => record);
}

describe("getSdkPayment", () => {
    it("reads the record of the hash, without its version", async () => {
        const h = harness();
        await seed(h, SEND);
        await expect(getSdkPayment(h.context, `0x${HASH}`)).resolves.toStrictEqual(SEND_READ);
    });

    it("is null for a hash the history holds no record of", async () => {
        const h = harness();
        await seed(h, SEND);
        await expect(getSdkPayment(h.context, `0x${OTHER_HASH}`)).resolves.toBeNull();
    });

    it("hands back a copy the host can change without changing the history", async () => {
        const h = harness();
        await seed(h, SEND);
        const read = await getSdkPayment(h.context, `0x${HASH}`);
        if (read === null) throw new Error("expected a record");
        read.status = "failed";
        await expect(getSdkPayment(h.context, `0x${HASH}`)).resolves.toStrictEqual(SEND_READ);
    });

    it("rethrows a record the store holds that is not one", async () => {
        const h = harness();
        h.storage.map.set(`fiber-lsp-sdk:payment-history:${HASH}`, JSON.stringify({ ...SEND, status: "sent" }));
        await expect(getSdkPayment(h.context, `0x${HASH}`)).rejects.toThrow(TypeError);
    });

    describe("the argument", () => {
        it.each<[string, unknown]>([
            ["no payment hash", undefined],
            ["a null payment hash", null],
            ["a payment hash that is not a string", 7],
            ["an empty payment hash", ""],
            ["a payment hash without the prefix", HASH],
            ["a payment hash one byte short", `0x${HASH.slice(0, -2)}`],
            ["a payment hash one byte long", `0x${HASH}aa`],
            ["a payment hash in upper case", `0x${HASH.toUpperCase()}`],
            ["a payment hash that is not hex", `0x${"zz".repeat(32)}`],
        ])("refuses %s, reading nothing", async (_, paymentHashHex) => {
            const h = harness();
            const thrown = await rejection(getSdkPayment(h.context, paymentHashHex as string));
            expect(thrown).toEqual(new TypeError("paymentHashHex must be 32 bytes of 0x-prefixed lowercase hex"));
            expect(thrown).toBeInstanceOf(TypeError);
            expect(h.storage.ops).toEqual([]);
        });
    });
});

function outOfRange(name: string, got: string): RangeError {
    return new RangeError(`${name} must be an integer between 0 and 9007199254740991, got ${got}`);
}

describe("listSdkPayments", () => {
    async function seedMany(h: Harness, count: number): Promise<string[]> {
        const hashes = Array.from({ length: count }, (_, at) => at.toString(16).padStart(2, "0").repeat(32));
        for (const [at, paymentHash] of hashes.entries()) await seed(h, receiveAt(paymentHash, CREATED_AT_MS + at * 1000));
        return [...hashes].reverse();
    }

    function hashesOf(records: SdkPaymentRecord[]): string[] {
        return records.map(({ paymentHashHex }) => paymentHashHex.slice(2));
    }

    it("is empty on a device that holds no payment", async () => {
        const h = harness();
        await expect(listSdkPayments(h.context)).resolves.toEqual([]);
    });

    it("lists the records newest first, ties by hash, without their version", async () => {
        const h = harness();
        await seed(h, SEND);
        await seed(h, receiveAt(THIRD_HASH, CREATED_AT_MS + 1));
        await seed(h, receiveAt(OTHER_HASH, CREATED_AT_MS));
        const listed = await listSdkPayments(h.context);
        expect(hashesOf(listed)).toEqual([THIRD_HASH, HASH, OTHER_HASH]);
        expect(listed[1]).toStrictEqual(SEND_READ);
    });

    it("hands back 20 records by default", async () => {
        const h = harness();
        const newestFirst = await seedMany(h, 25);
        expect(hashesOf(await listSdkPayments(h.context))).toEqual(newestFirst.slice(0, 20));
        expect(hashesOf(await listSdkPayments(h.context, {}))).toEqual(newestFirst.slice(0, 20));
    });

    it.each<[string, { limit?: number; offset?: number }, [number, number]]>([
        ["a limit", { limit: 3 }, [0, 3]],
        ["an offset", { offset: 22 }, [22, 25]],
        ["a limit and an offset", { limit: 2, offset: 4 }, [4, 6]],
        ["a limit of 0", { limit: 0 }, [0, 0]],
        ["an offset past the end", { offset: 25 }, [25, 25]],
        ["a limit past the end", { limit: 30, offset: 20 }, [20, 25]],
    ])("pages by %s", async (_, options, [from, to]) => {
        const h = harness();
        const newestFirst = await seedMany(h, 25);
        expect(hashesOf(await listSdkPayments(h.context, options))).toEqual(newestFirst.slice(from, to));
    });

    it("rethrows an entry whose record is missing", async () => {
        const h = harness();
        await seed(h, SEND);
        h.storage.map.delete(`fiber-lsp-sdk:payment-history:${HASH}`);
        await expect(listSdkPayments(h.context)).rejects.toEqual(
            new TypeError(`the payment history lists 0x${HASH}, whose record is missing`),
        );
    });

    describe("the arguments", () => {
        it.each<[string, unknown, TypeError | RangeError]>([
            ["options that are not an object", 7, new TypeError("options must be an object")],
            ["null options", null, new TypeError("options must be an object")],
            ["options that are an array", [], new TypeError("options must be an object")],
            ["a limit that is not a number", { limit: "20" }, outOfRange("options.limit", "20")],
            ["a null limit", { limit: null }, outOfRange("options.limit", "null")],
            ["a negative limit", { limit: -1 }, outOfRange("options.limit", "-1")],
            ["a fractional limit", { limit: 1.5 }, outOfRange("options.limit", "1.5")],
            ["a limit past the safe range", { limit: 2 ** 53 }, outOfRange("options.limit", "9007199254740992")],
            ["an offset that is not a number", { offset: "0" }, outOfRange("options.offset", "0")],
            ["a null offset", { offset: null }, outOfRange("options.offset", "null")],
            ["a negative offset", { offset: -1 }, outOfRange("options.offset", "-1")],
            ["a fractional offset", { offset: 0.5 }, outOfRange("options.offset", "0.5")],
            ["an offset past the safe range", { offset: 2 ** 53 }, outOfRange("options.offset", "9007199254740992")],
        ])("refuses %s, reading nothing", async (_, options, expected) => {
            const h = harness();
            const thrown = await rejection(listSdkPayments(h.context, options as never));
            expect(thrown).toEqual(expected);
            expect(thrown).toBeInstanceOf(expected.constructor);
            expect(h.storage.ops).toEqual([]);
        });
    });
});

describe("readSdkPayment", () => {
    function node(): { node: ScriptedNode; rpc: FiberRpcClient } {
        const scripted = new ScriptedNode();
        return { node: scripted, rpc: new FiberRpcClient({ url: URL, fetch: scripted.fetch }) };
    }

    // `get_payment`'s answer as a release build writes it.
    function answer(status: string, fee: string, failedError: string | null, paymentHash: string = HASH): unknown {
        return {
            payment_hash: `0x${paymentHash}`,
            payment_preimage: null,
            status,
            created_at: "0x1a115cf2760",
            last_updated_at: "0x1a115cf2b48",
            failed_error: failedError,
            fee,
            custom_records: null,
        };
    }

    it("asks the node for the hash, as it writes it, once, and reads its answer", async () => {
        const h = node();
        h.node.result(answer("Failed", "0x3e8", FIBER_REASON));
        await expect(readSdkPayment(h.rpc, HASH)).resolves.toMatchObject({
            status: "Failed",
            feeShannons: "1000",
            failedError: FIBER_REASON,
        });
        expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
    });

    it("is null on fiber's not found for the hash", async () => {
        const h = node();
        h.node.error(-32000, NOT_FOUND);
        await expect(readSdkPayment(h.rpc, HASH)).resolves.toBeNull();
    });

    it.each<[string, number, string]>([
        ["another hash's not found", -32000, `InvalidParameter: Payment session not found: Hash256(0x${OTHER_HASH})`],
        ["the not found under another code", -32602, NOT_FOUND],
        ["the not found with a trailing word", -32000, `${NOT_FOUND} yet`],
        ["any other refusal", -32000, FIBER_REASON],
    ])("rethrows %s as the node's error", async (_, code, message) => {
        const h = node();
        h.node.error(code, message);
        const thrown = await rejection(readSdkPayment(h.rpc, HASH));
        expect(thrown).toBeInstanceOf(RpcError);
        expect(thrown).toMatchObject({ code, message });
    });

    it("rethrows a transport failure as itself", async () => {
        const h = node();
        h.node.reject(new TypeError("fetch failed"));
        await expect(readSdkPayment(h.rpc, HASH)).rejects.toBeInstanceOf(RpcTransportError);
    });

    it("refuses an answer about another hash", async () => {
        const h = node();
        h.node.result(answer("Success", "0x3e8", null, OTHER_HASH));
        await expect(readSdkPayment(h.rpc, HASH)).rejects.toEqual(
            new Error(`the node answered the payment of 0x${HASH} with that of 0x${OTHER_HASH}`),
        );
    });
});
