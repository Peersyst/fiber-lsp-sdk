import type { DebitIntentRecord } from "../../../src/policy";
import { PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError } from "../../../src/rpc";
import type { SdkEvent, SdkPaymentRecord, StoredPaymentRecord } from "../../../src/sdk";
import { ActivityTracker, PaymentHistory, buildPaymentStep, getSdkPayment } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import { ScriptedNode } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import type { StepRun } from "../../utils/step-run";
import { live, pollFailedEvent, summarized } from "../../utils/step-run";
import { getPaymentCall } from "../../utils/payment-calls";
import { writes } from "../../utils/stored-records";

const URL = "http://127.0.0.1:8227";
const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const HASH = "3c".repeat(32);
const OTHER_HASH = "7e".repeat(32);
const INVOICE_HASH = "a374e42b6c28035e0c317346d635cc2a93a9b7920e88bd5b0abc96dc23bffc2f";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
// The intent's key holds the hash's first 20 bytes.
const INTENT_KEY = `fiber-lsp-sdk:intent:${"3c".repeat(20)}`;
const BUDGET = "1005000000";
const FIBER_REASON = "Failed to build route, PathFind error: no path found";
const NOT_FOUND = `InvalidParameter: Payment session not found: Hash256(0x${"3c".repeat(32)})`;
const NEVER_SENT = "the node holds no session of the payment: it was never sent";
const UNEXPLAINED = "the node reports the payment failed without a reason";
const RECORD_PREFIX = "fiber-lsp-sdk:payment-history:";
const CREATED_AT_MS = 1_791_367_200_000;
const NOW_MS = 1_791_367_206_000;

type Harness = {
    node: ScriptedNode;
    storage: InMemorySignerStorage;
    policy: PolicyEngine;
    activity: ActivityTracker;
    history: PaymentHistory;
    now: jest.Mock<number, []>;
    sending: Set<string>;
    reading: Set<string>;
    events: SdkEvent[];
    step: (run: StepRun) => Promise<void>;
};

function harness(onEmit: (event: SdkEvent) => void = () => undefined): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store);
    const activity = new ActivityTracker(store);
    const history = new PaymentHistory(store);
    const now = jest.fn<number, []>(() => NOW_MS);
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const sending = new Set<string>();
    const reading = new Set<string>();
    const step = buildPaymentStep({
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        policy,
        activity,
        history,
        now,
        sending,
        reading,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
    });
    return { node, storage, policy, activity, history, now, sending, reading, events, step };
}

function pendingRecord(paymentHash: string): StoredPaymentRecord {
    return {
        version: 1,
        paymentHashHex: `0x${paymentHash}`,
        direction: "send",
        status: "pending",
        amountShannons: "1000000000",
        invoice: "fibt10000000001send",
        description: "two coffees",
        maxFeeShannons: "5000000",
        feeShannons: null,
        failedReason: null,
        createdAtMs: CREATED_AT_MS,
        settledAtMs: null,
    };
}

function sentRecord(paymentHash: string): SdkPaymentRecord {
    return {
        paymentHashHex: `0x${paymentHash}`,
        direction: "send",
        status: "completed",
        amountShannons: "1000000000",
        invoice: "fibt10000000001send",
        description: "two coffees",
        maxFeeShannons: "5000000",
        feeShannons: "1000",
        failedReason: null,
        createdAtMs: CREATED_AT_MS,
        settledAtMs: NOW_MS,
    };
}

function failedRecord(paymentHash: string, reason: string): SdkPaymentRecord {
    return { ...sentRecord(paymentHash), status: "failed", feeShannons: null, failedReason: reason };
}

function sentEvent(paymentHash: string): SdkEvent {
    return { type: "PAYMENT_SENT", paymentHashHex: `0x${paymentHash}`, feeShannons: "1000", payment: sentRecord(paymentHash) };
}

function failedEvent(paymentHash: string, reason: string): SdkEvent {
    return { type: "PAYMENT_FAILED", paymentHashHex: `0x${paymentHash}`, reason, payment: failedRecord(paymentHash, reason) };
}

function withoutVersion({ version, ...record }: StoredPaymentRecord): SdkPaymentRecord {
    expect(version).toBe(1);
    return record;
}

function pendingRead(paymentHash: string): SdkPaymentRecord {
    return withoutVersion(pendingRecord(paymentHash));
}

async function seedRecord(h: Harness, record: StoredPaymentRecord): Promise<void> {
    await h.history.update(record.paymentHashHex.slice(2), () => record);
}

// No intent: the policy never opened it or already closed it.
async function watchedWithRecord(h: Harness, paymentHash: string): Promise<void> {
    await h.activity.watch("payment", paymentHash);
    await seedRecord(h, pendingRecord(paymentHash));
}

async function watchedWithIntent(h: Harness, paymentHash: string): Promise<void> {
    await watchedWithRecord(h, paymentHash);
    await h.policy.recordDebitIntent(paymentHash, BUDGET);
}

async function recordOf(h: Harness, paymentHash: string): Promise<SdkPaymentRecord | null> {
    return getSdkPayment(h, `0x${paymentHash}`);
}

async function paymentsOf(h: Harness): Promise<Record<string, { status: string | null }>> {
    return (await h.activity.read()).payments;
}

async function intentOf(h: Harness, paymentHash: string): Promise<DebitIntentRecord | null> {
    return h.policy.readDebitIntent(paymentHash);
}

function intentRecord(paymentHash: string, open: boolean): DebitIntentRecord {
    return { version: 1, paymentHash, maxShannons: BUDGET, open, channelIndexes: [] };
}

function paymentResult(paymentHash: string, status: string, failedError: string | null): unknown {
    return {
        payment_hash: `0x${paymentHash}`,
        status,
        created_at: "0x191dd9dec00",
        last_updated_at: "0x191dd9defe8",
        failed_error: failedError,
        fee: "0x3e8",
    };
}

describe("buildPaymentStep", () => {
    describe("nothing watched", () => {
        it("calls nothing when no payment was ever watched", async () => {
            const h = harness();
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
            expect(h.events).toEqual([]);
            expect(writes(h.storage)).toEqual([]);
        });

        it("calls nothing when only channels and invoices are watched", async () => {
            const h = harness();
            await h.activity.watch("channel", CHANNEL_ID);
            await h.activity.watch("invoice", INVOICE_HASH);
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
        });

        it("calls nothing once the last watched payment was sent", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
        });
    });

    describe("a payment in flight", () => {
        it.each(["Created", "Inflight"])("emits and writes nothing for %s, and keeps watching it with its intent open", async (status) => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.storage.ops.length = 0;
            h.node.result(paymentResult(HASH, status, null));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
            expect(h.events).toEqual([]);
            expect(writes(h.storage)).toEqual([]);
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
        });

        it("ignores an error fiber reports beside an inflight status", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Inflight", FIBER_REASON));
            await h.step(live());
            expect(h.events).toEqual([]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
        });
    });

    describe("a payment sent", () => {
        it("closes its intent, emits PAYMENT_SENT, then stops watching it", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
            expect(h.events).toStrictEqual([sentEvent(HASH)]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("emits PAYMENT_SENT for one with no intent, recording none", async () => {
            const h = harness();
            await watchedWithRecord(h, HASH);
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(h.events).toStrictEqual([sentEvent(HASH)]);
            expect(await intentOf(h, HASH)).toBeNull();
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("answers each watched payment in turn", async () => {
            const h = harness();
            await watchedWithIntent(h, OTHER_HASH);
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(OTHER_HASH, "Inflight", null)).result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(OTHER_HASH), getPaymentCall(HASH)]);
            expect(h.events).toStrictEqual([sentEvent(HASH)]);
            expect(await intentOf(h, OTHER_HASH)).toStrictEqual(intentRecord(OTHER_HASH, true));
            expect(await paymentsOf(h)).toStrictEqual({ [OTHER_HASH]: { status: null } });
        });
    });

    describe("a payment failed", () => {
        it("closes its intent, emits PAYMENT_FAILED with fiber's reason verbatim, then stops watching it", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Failed", FIBER_REASON));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
            expect(h.events).toStrictEqual([failedEvent(HASH, FIBER_REASON)]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("gives the SDK's reason when fiber gives none", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Failed", null));
            await h.step(live());
            expect(h.events).toStrictEqual([failedEvent(HASH, UNEXPLAINED)]);
        });

        it("keeps an empty reason of fiber's as it is", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Failed", ""));
            await h.step(live());
            expect(h.events).toStrictEqual([failedEvent(HASH, "")]);
        });

        it("emits PAYMENT_FAILED for one with no intent, recording none", async () => {
            const h = harness();
            await watchedWithRecord(h, HASH);
            h.node.result(paymentResult(HASH, "Failed", FIBER_REASON));
            await h.step(live());
            expect(h.events).toStrictEqual([failedEvent(HASH, FIBER_REASON)]);
            expect(await intentOf(h, HASH)).toBeNull();
            expect(await paymentsOf(h)).toStrictEqual({});
        });
    });

    describe("a payment the node holds no session of", () => {
        it("closes its intent, emits PAYMENT_FAILED with the SDK's reason, then stops watching it", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
            expect(h.events).toStrictEqual([failedEvent(HASH, NEVER_SENT)]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("emits PAYMENT_FAILED for one with no intent, recording none", async () => {
            const h = harness();
            await watchedWithRecord(h, HASH);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(h.events).toStrictEqual([failedEvent(HASH, NEVER_SENT)]);
            expect(await intentOf(h, HASH)).toBeNull();
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("emits PAYMENT_FAILED for a twin left watched with no intent of its own, the twin's intent untouched", async () => {
            const h = harness();
            // Shares with HASH the 20 bytes a TLC's witness binds, so the intent's key is HASH's.
            const twin = `${"3c".repeat(20)}${"00".repeat(12)}`;
            await h.policy.recordDebitIntent(twin, BUDGET);
            await watchedWithRecord(h, HASH);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(h.events).toStrictEqual([failedEvent(HASH, NEVER_SENT)]);
            expect(await intentOf(h, HASH)).toBeNull();
            expect(await intentOf(h, twin)).toStrictEqual(intentRecord(twin, true));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it.each<[string, number, string]>([
            ["another hash", -32000, `InvalidParameter: Payment session not found: Hash256(0x${"7e".repeat(32)})`],
            ["the hash in uppercase", -32000, `InvalidParameter: Payment session not found: Hash256(0x${"3C".repeat(32)})`],
            ["the hash bare", -32000, `InvalidParameter: Payment session not found: 0x${"3c".repeat(32)}`],
            ["no error kind", -32000, `Payment session not found: Hash256(0x${"3c".repeat(32)})`],
            ["text past it", -32000, `${NOT_FOUND} `],
            ["another code", -32603, NOT_FOUND],
        ])("reports fiber's text with %s as poll_failed naming the payment, ending nothing", async (_, code, message) => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.storage.ops.length = 0;
            h.node.error(code, message);
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the payment poll of 0x${HASH} failed: ${message}`, expect.any(RpcError)),
            ]);
            expect(writes(h.storage)).toEqual([]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("reports a refusal that only looks like fiber's not found as poll_failed, ending nothing", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            const lookalike = { name: "RpcError", code: -32000, message: NOT_FOUND };
            const read = jest.spyOn(FiberRpcClient.prototype, "getPayment").mockRejectedValue(lookalike);
            try {
                await h.step(live());
            } finally {
                read.mockRestore();
            }
            expect(summarized(h.events)).toStrictEqual([pollFailedEvent(`the payment poll of 0x${HASH} failed`, lookalike)]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });
    });

    describe("a payment whose transfer is in progress", () => {
        it("is skipped, calling, emitting and writing nothing for it, while the others are answered", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            await watchedWithIntent(h, OTHER_HASH);
            h.sending.add(HASH);
            h.storage.ops.length = 0;
            h.node.result(paymentResult(OTHER_HASH, "Success", null));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(OTHER_HASH)]);
            expect(h.events).toEqual([sentEvent(OTHER_HASH)]);
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
        });

        it("is read at the next tick once its transfer settled", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.sending.add(HASH);
            await h.step(live());
            h.sending.delete(HASH);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
            expect(h.events).toEqual([failedEvent(HASH, NEVER_SENT)]);
        });

        it("is judged when its turn comes, not when the tick began", async () => {
            const h = harness();
            await watchedWithIntent(h, OTHER_HASH);
            await watchedWithIntent(h, HASH);
            h.node.onCall("get_payment", () => h.sending.add(HASH));
            h.node.result(paymentResult(OTHER_HASH, "Inflight", null));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(OTHER_HASH)]);
        });

        it("is never held as read", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.sending.add(HASH);
            const add = jest.spyOn(h.reading, "add");
            await h.step(live());
            expect(add).not.toHaveBeenCalled();
        });
    });

    describe("a payment being read", () => {
        it("is held as read from its get_payment through its close, its event and its forget", async () => {
            const held: Record<string, boolean> = {};
            const h = harness(() => {
                held.emit = h.reading.has(HASH);
            });
            await watchedWithIntent(h, HASH);
            h.node.onCall("get_payment", () => {
                held.read = h.reading.has(HASH);
            });
            const close = h.policy.closeDebitIntent.bind(h.policy);
            jest.spyOn(h.policy, "closeDebitIntent").mockImplementation(async (paymentHash) => {
                held.close = h.reading.has(HASH);
                await close(paymentHash);
            });
            const forget = h.activity.forget.bind(h.activity);
            jest.spyOn(h.activity, "forget").mockImplementation(async (kind, id) => {
                held.forget = h.reading.has(HASH);
                await forget(kind, id);
            });
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(held).toEqual({ read: true, close: true, emit: true, forget: true });
            expect([...h.reading]).toEqual([]);
        });

        it.each<[string, (node: ScriptedNode) => void, (run: StepRun) => void]>([
            ["Created", (node) => node.result(paymentResult(HASH, "Created", null)), () => undefined],
            ["Inflight", (node) => node.result(paymentResult(HASH, "Inflight", null)), () => undefined],
            ["Success", (node) => node.result(paymentResult(HASH, "Success", null)), () => undefined],
            ["Failed", (node) => node.result(paymentResult(HASH, "Failed", FIBER_REASON)), () => undefined],
            ["no session", (node) => node.error(-32000, NOT_FOUND), () => undefined],
            ["a refused read", (node) => node.error(-32000, FIBER_REASON), () => undefined],
            ["a read with no answer", (node) => node.reject(new Error("offline")), () => undefined],
            ["another payment's answer", (node) => node.result(paymentResult(OTHER_HASH, "Success", null)), () => undefined],
            [
                "a run abandoned during the read",
                (node) => node.result(paymentResult(HASH, "Success", null)),
                (run) => {
                    run.abandoned = true;
                },
            ],
        ])("is let go after %s", async (_, answer, during) => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            const run = live();
            h.node.onCall("get_payment", () => during(run));
            answer(h.node);
            await h.step(run);
            expect([...h.reading]).toEqual([]);
        });

        it("leaves alone a payment no longer watched when its answer arrives, ending nothing", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.onCall("get_payment", () => {
                void h.activity.forget("payment", HASH);
            });
            h.node.result(paymentResult(HASH, "Failed", FIBER_REASON));
            await h.step(live());
            expect(h.events).toEqual([]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
        });
    });

    describe("the order", () => {
        it.each<[string, unknown, SdkEvent["type"]]>([
            ["sent", paymentResult(HASH, "Success", null), "PAYMENT_SENT"],
            ["failed", paymentResult(HASH, "Failed", FIBER_REASON), "PAYMENT_FAILED"],
        ])("closes the intent of one %s, then settles its record, then emits, then stops watching it", async (_, result, type) => {
            const order: string[] = [];
            const h = harness((event) => order.push(event.type));
            await watchedWithIntent(h, HASH);
            const close = h.policy.closeDebitIntent.bind(h.policy);
            jest.spyOn(h.policy, "closeDebitIntent").mockImplementation(async (paymentHash) => {
                order.push("close");
                await close(paymentHash);
            });
            const update = h.history.update.bind(h.history);
            jest.spyOn(h.history, "update").mockImplementation(async (...args) => {
                order.push("record");
                return update(...args);
            });
            const forget = h.activity.forget.bind(h.activity);
            jest.spyOn(h.activity, "forget").mockImplementation(async (...args) => {
                order.push("forget");
                await forget(...args);
            });
            h.node.result(result);
            await h.step(live());
            expect(order).toEqual(["close", "record", type, "forget"]);
        });

        it("shows the listener the intent closed, the record settled and the payment still watched", async () => {
            const seen: unknown[] = [];
            const h = harness(() => {
                const intent = h.storage.map.get(INTENT_KEY);
                const record = h.storage.map.get(RECORD_PREFIX + HASH);
                const activity = h.storage.map.get(ACTIVITY_KEY);
                if (intent === undefined || record === undefined || activity === undefined) throw new Error("the records are missing");
                seen.push(
                    (JSON.parse(intent) as { open: unknown }).open,
                    (JSON.parse(record) as { status: unknown }).status,
                    (JSON.parse(activity) as { payments: unknown }).payments,
                );
            });
            await watchedWithIntent(h, HASH);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(seen).toStrictEqual([false, "failed", { [HASH]: { status: null } }]);
            expect(await paymentsOf(h)).toStrictEqual({});
        });
    });

    describe("the history", () => {
        it.each<[string, unknown, SdkPaymentRecord]>([
            ["sent", paymentResult(HASH, "Success", null), sentRecord(HASH)],
            ["failed", paymentResult(HASH, "Failed", FIBER_REASON), failedRecord(HASH, FIBER_REASON)],
        ])(
            "settles the record of one %s at the clock's reading, the event carrying it as getPayment reads it",
            async (_, result, expected) => {
                const h = harness();
                await watchedWithIntent(h, HASH);
                h.node.result(result);
                await h.step(live());
                expect(await recordOf(h, HASH)).toStrictEqual(expected);
                const [event] = h.events;
                expect(event !== undefined && "payment" in event ? event.payment : undefined).toStrictEqual(await recordOf(h, HASH));
                expect(h.now).toHaveBeenCalledTimes(1);
            },
        );

        it("fails the record of one the node holds no session of with the SDK's reason", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(await recordOf(h, HASH)).toStrictEqual(failedRecord(HASH, NEVER_SENT));
        });

        it("fails the record with the SDK's reason when fiber gives none", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Failed", null));
            await h.step(live());
            expect(await recordOf(h, HASH)).toStrictEqual(failedRecord(HASH, UNEXPLAINED));
        });

        it("turns a failed record completed on fiber's Success, its reason cleared: the Failed was false", async () => {
            const h = harness();
            await h.activity.watch("payment", HASH);
            await seedRecord(h, {
                ...pendingRecord(HASH),
                status: "failed",
                failedReason: FIBER_REASON,
                settledAtMs: CREATED_AT_MS + 1000,
            });
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(await recordOf(h, HASH)).toStrictEqual(sentRecord(HASH));
            expect(h.events).toStrictEqual([sentEvent(HASH)]);
        });

        it("leaves a completed record as it is on a Success delivered again, emitting it as stored", async () => {
            const h = harness();
            await h.activity.watch("payment", HASH);
            const completed = { version: 1 as const, ...sentRecord(HASH), settledAtMs: CREATED_AT_MS + 2000 };
            await seedRecord(h, completed);
            h.storage.ops.length = 0;
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            const stored = withoutVersion(completed);
            expect(await recordOf(h, HASH)).toStrictEqual(stored);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_SENT", paymentHashHex: `0x${HASH}`, feeShannons: "1000", payment: stored }]);
            expect(writes(h.storage)).toEqual([ACTIVITY_KEY]);
        });

        it("announces nothing for a completed record answered Failed, keeping it completed, closing its intent and forgetting it", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            const completed = { version: 1 as const, ...sentRecord(HASH), settledAtMs: CREATED_AT_MS + 2000 };
            await seedRecord(h, completed);
            h.storage.ops.length = 0;
            h.node.result(paymentResult(HASH, "Failed", FIBER_REASON));
            await h.step(live());
            expect(h.events).toEqual([]);
            expect(await recordOf(h, HASH)).toStrictEqual(withoutVersion(completed));
            expect(writes(h.storage)).toEqual([INTENT_KEY, ACTIVITY_KEY]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("ends silently a watch with no record and no session: it stopped before the node heard of it", async () => {
            const h = harness();
            await h.activity.watch("payment", HASH);
            await h.policy.recordDebitIntent(HASH, BUDGET);
            h.node.error(-32000, NOT_FOUND);
            await h.step(live());
            expect(h.events).toEqual([]);
            expect(await recordOf(h, HASH)).toBeNull();
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it.each<[string, unknown]>([
            ["Success", paymentResult(HASH, "Success", null)],
            ["Failed", paymentResult(HASH, "Failed", FIBER_REASON)],
        ])("reports a watch with no record whose session the node holds as %s as poll_failed, keeping it watched", async (_, result) => {
            const h = harness();
            await h.activity.watch("payment", HASH);
            h.node.result(result).result(result);
            await h.step(live());
            await h.step(live());
            const failure = pollFailedEvent(
                `the payment poll of 0x${HASH} failed: the node holds a payment under 0x${HASH}, whose record is missing`,
                expect.any(TypeError),
            );
            expect(summarized(h.events)).toStrictEqual([failure, failure]);
            expect(await recordOf(h, HASH)).toBeNull();
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("emits nothing and keeps watching after a record write that failed, the intent closed, then ends it on the next tick", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            jest.spyOn(h.history, "update").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node.result(paymentResult(HASH, "Success", null)).result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(await recordOf(h, HASH)).toStrictEqual(pendingRead(HASH));
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the payment poll of 0x${HASH} failed: storage is full`, expect.any(TypeError)),
                sentEvent(HASH),
            ]);
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("reports a clock the step refuses as poll_failed, the record left pending and the payment watched", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.now.mockReturnValue(-1);
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(
                    `the payment poll of 0x${HASH} failed: now() must be an integer between 0 and 9007199254740991, got -1`,
                    expect.any(RangeError),
                ),
            ]);
            expect(await recordOf(h, HASH)).toStrictEqual(pendingRead(HASH));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("emits nothing and keeps watching once abandoned during the record write, and emits the same record on the next tick", async () => {
            const h = harness();
            const run = live();
            await watchedWithIntent(h, HASH);
            const update = h.history.update.bind(h.history);
            jest.spyOn(h.history, "update").mockImplementationOnce(async (...args) => {
                const record = await update(...args);
                run.abandoned = true;
                return record;
            });
            h.node.result(paymentResult(HASH, "Success", null)).result(paymentResult(HASH, "Success", null));
            await h.step(run);
            expect(h.events).toEqual([]);
            expect(await recordOf(h, HASH)).toStrictEqual(sentRecord(HASH));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            h.now.mockReturnValue(NOW_MS + 5000);
            await h.step(live());
            expect(h.events).toStrictEqual([sentEvent(HASH)]);
            expect(await paymentsOf(h)).toStrictEqual({});
        });
    });

    describe("a failure", () => {
        it("reports another refusal of the node as poll_failed naming the payment, then answers the next one", async () => {
            const h = harness();
            await watchedWithIntent(h, OTHER_HASH);
            await watchedWithIntent(h, HASH);
            h.node.error(-32000, "Failed to get payment").result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(h.node.calls()).toEqual([getPaymentCall(OTHER_HASH), getPaymentCall(HASH)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the payment poll of 0x${OTHER_HASH} failed: Failed to get payment`, expect.any(RpcError)),
                sentEvent(HASH),
            ]);
            expect(await intentOf(h, OTHER_HASH)).toStrictEqual(intentRecord(OTHER_HASH, true));
            expect(await paymentsOf(h)).toStrictEqual({ [OTHER_HASH]: { status: null } });
        });

        it("reports the same refusal on every tick, keeping the payment watched", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.error(-32000, "Failed to get payment").error(-32000, "Failed to get payment");
            await h.step(live());
            await h.step(live());
            const failure = pollFailedEvent(`the payment poll of 0x${HASH} failed: Failed to get payment`, expect.any(RpcError));
            expect(summarized(h.events)).toStrictEqual([failure, failure]);
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("reports a status it does not know as poll_failed naming the payment", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(HASH, "Refunded", null));
            await h.step(live());
            expect(h.events).toHaveLength(1);
            expect(h.events[0]).toMatchObject({ error: { code: "poll_failed", cause: expect.any(RpcResponseError) } });
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
        });

        it.each(["Created", "Inflight", "Success", "Failed"])(
            "reports a %s answered for another payment as poll_failed, ending nothing",
            async (status) => {
                const h = harness();
                await watchedWithIntent(h, HASH);
                h.storage.ops.length = 0;
                h.node.result(paymentResult(OTHER_HASH, status, null));
                await h.step(live());
                expect(summarized(h.events)).toStrictEqual([
                    pollFailedEvent(
                        `the payment poll of 0x${HASH} failed: the node answered the payment of 0x${HASH} with that of 0x${OTHER_HASH}`,
                        expect.any(Error),
                    ),
                ]);
                expect(writes(h.storage)).toEqual([]);
                expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
                expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            },
        );

        it("rejects the step when the activity list cannot be read, calling nothing", async () => {
            const h = harness();
            h.storage.map.set(ACTIVITY_KEY, "{");
            const error = await rejection(h.step(live()));
            expect(error).toEqual(new TypeError(`stored value at ${ACTIVITY_KEY} is not valid JSON`));
            expect(h.node.calls()).toEqual([]);
        });

        it("emits nothing and keeps watching after an intent that cannot be read, then ends it on the next tick", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            jest.spyOn(h.policy, "readDebitIntent").mockRejectedValueOnce(new TypeError("storage is unreadable"));
            h.node.result(paymentResult(HASH, "Success", null)).result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the payment poll of 0x${HASH} failed: storage is unreadable`, expect.any(TypeError)),
                sentEvent(HASH),
            ]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("emits nothing and keeps watching after a close that failed, then ends it on the next tick", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            jest.spyOn(h.policy, "closeDebitIntent").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node.result(paymentResult(HASH, "Failed", FIBER_REASON)).result(paymentResult(HASH, "Failed", FIBER_REASON));
            await h.step(live());
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the payment poll of 0x${HASH} failed: storage is full`, expect.any(TypeError)),
                failedEvent(HASH, FIBER_REASON),
            ]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("emits the event again on the next tick after a forget that failed, the intent left closed", async () => {
            const h = harness();
            await watchedWithIntent(h, HASH);
            jest.spyOn(h.activity, "forget").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node.result(paymentResult(HASH, "Success", null)).result(paymentResult(HASH, "Success", null));
            await h.step(live());
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                sentEvent(HASH),
                pollFailedEvent(`the payment poll of 0x${HASH} failed: storage is full`, expect.any(TypeError)),
                sentEvent(HASH),
            ]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });
    });

    describe("the host's listener", () => {
        it("keeps answering when it throws, each payment ended", async () => {
            const h = harness(() => {
                throw new Error("the host's listener failed");
            });
            await watchedWithIntent(h, OTHER_HASH);
            await watchedWithIntent(h, HASH);
            h.node.result(paymentResult(OTHER_HASH, "Failed", FIBER_REASON)).result(paymentResult(HASH, "Success", null));
            await expect(h.step(live())).resolves.toBeUndefined();
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_FAILED", "PAYMENT_SENT"]);
            expect(h.node.calls()).toEqual([getPaymentCall(OTHER_HASH), getPaymentCall(HASH)]);
            expect(await intentOf(h, OTHER_HASH)).toStrictEqual(intentRecord(OTHER_HASH, false));
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });
    });

    describe("an abandoned run", () => {
        it.each<[string, (node: ScriptedNode) => void]>([
            ["it was sent", (node) => node.result(paymentResult(HASH, "Success", null))],
            ["the node holds no session of it", (node) => node.error(-32000, NOT_FOUND)],
        ])(
            "reads, writes and emits nothing, and answers no further payment, once abandoned during get_payment of one %s",
            async (_, answer) => {
                const h = harness();
                const run = live();
                await watchedWithIntent(h, HASH);
                await watchedWithIntent(h, OTHER_HASH);
                const read = jest.spyOn(h.policy, "readDebitIntent");
                h.storage.ops.length = 0;
                h.node.onCall("get_payment", () => (run.abandoned = true));
                answer(h.node);
                await h.step(run);
                expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
                expect(read).not.toHaveBeenCalled();
                expect(h.events).toEqual([]);
                expect(writes(h.storage)).toEqual([]);
            },
        );

        it("closes nothing once abandoned while the intent is read, and ends the payment on the next tick", async () => {
            const h = harness();
            const run = live();
            await watchedWithIntent(h, HASH);
            const read = h.policy.readDebitIntent.bind(h.policy);
            jest.spyOn(h.policy, "readDebitIntent").mockImplementationOnce(async (paymentHash) => {
                const record = await read(paymentHash);
                run.abandoned = true;
                return record;
            });
            h.node.result(paymentResult(HASH, "Failed", FIBER_REASON)).result(paymentResult(HASH, "Failed", FIBER_REASON));
            await h.step(run);
            expect(h.events).toEqual([]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, true));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            await h.step(live());
            expect(h.events).toStrictEqual([failedEvent(HASH, FIBER_REASON)]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("emits nothing for one with no intent once abandoned while its intent is read", async () => {
            const h = harness();
            const run = live();
            await watchedWithRecord(h, HASH);
            const read = h.policy.readDebitIntent.bind(h.policy);
            jest.spyOn(h.policy, "readDebitIntent").mockImplementationOnce(async (paymentHash) => {
                const record = await read(paymentHash);
                run.abandoned = true;
                return record;
            });
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(run);
            expect(h.events).toEqual([]);
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("emits nothing and keeps watching once abandoned during the close, and emits on the next tick", async () => {
            const h = harness();
            const run = live();
            await watchedWithIntent(h, HASH);
            const close = h.policy.closeDebitIntent.bind(h.policy);
            jest.spyOn(h.policy, "closeDebitIntent").mockImplementationOnce(async (paymentHash) => {
                await close(paymentHash);
                run.abandoned = true;
            });
            h.node.result(paymentResult(HASH, "Success", null)).result(paymentResult(HASH, "Success", null));
            await h.step(run);
            expect(h.events).toEqual([]);
            expect(await intentOf(h, HASH)).toStrictEqual(intentRecord(HASH, false));
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            await h.step(live());
            expect(h.events).toStrictEqual([sentEvent(HASH)]);
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it.each<[SdkEvent["type"], unknown]>([
            ["PAYMENT_SENT", paymentResult(HASH, "Success", null)],
            ["PAYMENT_FAILED", paymentResult(HASH, "Failed", FIBER_REASON)],
        ])("keeps watching once abandoned by %s, and emits it again on the next tick", async (type, result) => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watchedWithIntent(h, HASH);
            h.node.result(result).result(result);
            await h.step(run);
            expect(await paymentsOf(h)).toStrictEqual({ [HASH]: { status: null } });
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual([type, type]);
            expect(await paymentsOf(h)).toStrictEqual({});
        });

        it("answers no further payment once abandoned by an event", async () => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watchedWithIntent(h, HASH);
            await watchedWithIntent(h, OTHER_HASH);
            h.node.result(paymentResult(HASH, "Success", null));
            await h.step(run);
            expect(h.node.calls()).toEqual([getPaymentCall(HASH)]);
            expect(await intentOf(h, OTHER_HASH)).toStrictEqual(intentRecord(OTHER_HASH, true));
        });
    });
});
