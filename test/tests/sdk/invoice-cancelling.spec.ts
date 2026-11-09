import { HoldInvoiceError, PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RPC_CALL_FAILED_CODE, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkInvoiceCancellingContext } from "../../../src/sdk";
import { ActivityPoller, SdkError, cancelInvoiceOnNode, cancelSdkInvoice } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import { storedAt, writes } from "../../utils/stored-records";

const URL = "http://127.0.0.1:8227";
const HASH = "a374e42b6c28035e0c317346d635cc2a93a9b7920e88bd5b0abc96dc23bffc2f";
const HASH_HEX = `0x${HASH}`;
const INDEX = 1_790_812_800_000;
const AMOUNT = "2250000000";
const RECORD_KEY = `fiber-lsp-sdk:invoice:${HASH.slice(0, 40)}`;
const CANCEL_CALL: SentCall = { method: "cancel_invoice", params: { payment_hash: HASH_HEX } };
const CANCELLED_ANSWER = { invoice_address: "fibt1", status: "Cancelled" };
const ALREADY_CANCELLED = "invoice can not be canceled, current status: Cancelled";
const ALREADY_PAID = "invoice can not be canceled, current status: Paid";
const NOT_FOUND = "invoice not found";

type Harness = {
    storage: InMemorySignerStorage;
    policy: PolicyEngine;
    node: ScriptedNode;
    pollNow: jest.SpyInstance<void, []>;
    context: SdkInvoiceCancellingContext;
};

function harness(): Harness {
    const storage = new InMemorySignerStorage();
    const policy = new PolicyEngine(new SignerStore(storage));
    const node = new ScriptedNode();
    const poller = new ActivityPoller({
        timer: new TimerMock(),
        intervalMs: 5_000,
        stepTimeoutMs: 30_000,
        steps: [],
        emit: () => undefined,
    });
    const pollNow = jest.spyOn(poller, "pollNow");
    return { storage, policy, node, pollNow, context: { rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }), policy, poller } };
}

async function recorded(): Promise<Harness> {
    const h = harness();
    await h.policy.recordHoldInvoice(HASH, AMOUNT, "ckb-hash", INDEX);
    h.storage.ops.length = 0;
    return h;
}

function seedReleased(h: Harness): void {
    h.storage.map.set(
        RECORD_KEY,
        JSON.stringify({
            version: 1,
            paymentHash: HASH,
            amountShannons: AMOUNT,
            hashAlgorithm: "ckb-hash",
            invoiceIndex: INDEX,
            released: true,
            channelIndexes: [],
        }),
    );
}

function storedCancelled(h: Harness): unknown {
    return (storedAt(h.storage, RECORD_KEY) as { cancelled?: unknown }).cancelled;
}

describe("cancelSdkInvoice", () => {
    it("marks the record, asks the node to cancel, then asks for a tick, in that order", async () => {
        const order: string[] = [];
        const h = await recorded();
        const mark = h.policy.markHoldInvoiceCancelled.bind(h.policy);
        jest.spyOn(h.policy, "markHoldInvoiceCancelled").mockImplementation(async (paymentHash) => {
            await mark(paymentHash);
            order.push("mark");
        });
        h.pollNow.mockImplementation(() => order.push("poll"));
        h.node.onCall("cancel_invoice", () => order.push("node")).result(CANCELLED_ANSWER);
        await expect(cancelSdkInvoice(h.context, HASH_HEX)).resolves.toBeUndefined();
        expect(order).toEqual(["mark", "node", "poll"]);
        expect(h.node.calls()).toEqual([CANCEL_CALL]);
    });

    it("has written the mark by the time the node is asked", async () => {
        const h = await recorded();
        let atCall: unknown;
        h.node.onCall("cancel_invoice", () => (atCall = storedCancelled(h))).result(CANCELLED_ANSWER);
        await cancelSdkInvoice(h.context, HASH_HEX);
        expect(atCall).toBe(true);
    });

    it("hands the policy the hash in the store's form", async () => {
        const h = await recorded();
        const mark = jest.spyOn(h.policy, "markHoldInvoiceCancelled");
        h.node.result(CANCELLED_ANSWER);
        await cancelSdkInvoice(h.context, HASH_HEX);
        expect(mark).toHaveBeenCalledWith(HASH);
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
        ])("refuses %s, reading, writing and calling nothing", async (_, paymentHashHex) => {
            const h = await recorded();
            const thrown = await rejection(cancelSdkInvoice(h.context, paymentHashHex as string));
            expect(thrown).toEqual(new TypeError("paymentHashHex must be 32 bytes of 0x-prefixed lowercase hex"));
            expect(thrown).toBeInstanceOf(TypeError);
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });
    });

    describe("what the policy refuses", () => {
        it("names an invoice never recorded as unknown_invoice, its refusal the cause, calling the node for nothing", async () => {
            const h = harness();
            const thrown = await rejection(cancelSdkInvoice(h.context, HASH_HEX));
            expect(thrown).toBeInstanceOf(SdkError);
            expect(thrown).toEqual(new SdkError("unknown_invoice", `this device recorded no invoice ${HASH_HEX}`));
            expect((thrown as SdkError).code).toBe("unknown_invoice");
            expect((thrown as SdkError).cause).toMatchObject({ code: "not_recorded" });
            expect((thrown as SdkError).cause).toBeInstanceOf(HoldInvoiceError);
            expect(h.node.calls()).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("names a released invoice as invoice_released, its refusal the cause, calling the node for nothing", async () => {
            const h = harness();
            seedReleased(h);
            const thrown = await rejection(cancelSdkInvoice(h.context, HASH_HEX));
            expect(thrown).toBeInstanceOf(SdkError);
            expect(thrown).toEqual(
                new SdkError("invoice_released", `the invoice ${HASH_HEX} cannot be cancelled: its preimage was released`),
            );
            expect((thrown as SdkError).code).toBe("invoice_released");
            expect((thrown as SdkError).cause).toMatchObject({ code: "released" });
            expect((thrown as SdkError).cause).toBeInstanceOf(HoldInvoiceError);
            expect(h.node.calls()).toEqual([]);
            expect(writes(h.storage)).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("rethrows the policy's refusal under any other code as itself", async () => {
            const h = await recorded();
            const error = new HoldInvoiceError("algorithm_mismatch", "another algorithm");
            jest.spyOn(h.policy, "markHoldInvoiceCancelled").mockRejectedValue(error);
            expect(await rejection(cancelSdkInvoice(h.context, HASH_HEX))).toBe(error);
            expect(h.node.calls()).toEqual([]);
        });

        it("rethrows a broken store as itself", async () => {
            const h = await recorded();
            const error = new Error("storage offline");
            jest.spyOn(h.policy, "markHoldInvoiceCancelled").mockRejectedValue(error);
            expect(await rejection(cancelSdkInvoice(h.context, HASH_HEX))).toBe(error);
            expect(h.node.calls()).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });
    });

    describe("the node", () => {
        it("takes fiber's already cancelled as the cancel done, asking for a tick", async () => {
            const h = await recorded();
            h.node.error(RPC_CALL_FAILED_CODE, ALREADY_CANCELLED);
            await expect(cancelSdkInvoice(h.context, HASH_HEX)).resolves.toBeUndefined();
            expect(h.pollNow).toHaveBeenCalledTimes(1);
        });

        it("repeats a cancel already marked, writing the mark once", async () => {
            const h = await recorded();
            h.node.result(CANCELLED_ANSWER).error(RPC_CALL_FAILED_CODE, ALREADY_CANCELLED);
            await cancelSdkInvoice(h.context, HASH_HEX);
            const firstWrites = writes(h.storage).length;
            await cancelSdkInvoice(h.context, HASH_HEX);
            expect(writes(h.storage)).toHaveLength(firstWrites);
            expect(h.node.calls()).toEqual([CANCEL_CALL, CANCEL_CALL]);
        });

        it.each<[string, (h: Harness) => void, new (...args: never[]) => Error]>([
            ["fiber's already paid", (h) => h.node.error(RPC_CALL_FAILED_CODE, ALREADY_PAID), RpcError],
            ["fiber's unknown invoice", (h) => h.node.error(RPC_CALL_FAILED_CODE, NOT_FOUND), RpcError],
            ["already cancelled under another code", (h) => h.node.error(-32601, ALREADY_CANCELLED), RpcError],
            ["a message that only starts like it", (h) => h.node.error(RPC_CALL_FAILED_CODE, `${ALREADY_CANCELLED}.`), RpcError],
            ["a transport failure", (h) => h.node.reject(new Error("offline")), RpcTransportError],
            ["an answer that is not an invoice", (h) => h.node.result(true), RpcResponseError],
        ])("lets %s through, leaving the mark and asking for no tick", async (_, answer, errorClass) => {
            const h = await recorded();
            answer(h);
            expect(await rejection(cancelSdkInvoice(h.context, HASH_HEX))).toBeInstanceOf(errorClass);
            expect(storedCancelled(h)).toBe(true);
            expect(h.node.calls()).toEqual([CANCEL_CALL]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("keeps a failed cancel's mark in force: the preimage is refused, and a retry completes it", async () => {
            const h = await recorded();
            h.node.reject(new Error("offline")).result(CANCELLED_ANSWER);
            await rejection(cancelSdkInvoice(h.context, HASH_HEX));
            await expect(h.policy.markHoldInvoiceReleased(HASH, { now: () => INDEX, releaseMarginMs: () => 0n })).rejects.toMatchObject({
                code: "cancelled",
            });
            await expect(cancelSdkInvoice(h.context, HASH_HEX)).resolves.toBeUndefined();
            expect(h.node.calls()).toEqual([CANCEL_CALL, CANCEL_CALL]);
        });
    });
});

describe("cancelInvoiceOnNode", () => {
    it("sends the hash as the node writes it", async () => {
        const h = harness();
        h.node.result(CANCELLED_ANSWER);
        await expect(cancelInvoiceOnNode(h.context.rpc, HASH)).resolves.toBeUndefined();
        expect(h.node.calls()).toEqual([CANCEL_CALL]);
    });

    it("resolves on fiber's already cancelled", async () => {
        const h = harness();
        h.node.error(RPC_CALL_FAILED_CODE, ALREADY_CANCELLED);
        await expect(cancelInvoiceOnNode(h.context.rpc, HASH)).resolves.toBeUndefined();
    });

    it("rejects on any other refusal", async () => {
        const h = harness();
        h.node.error(RPC_CALL_FAILED_CODE, NOT_FOUND);
        expect(await rejection(cancelInvoiceOnNode(h.context.rpc, HASH))).toMatchObject({ message: NOT_FOUND });
    });
});
