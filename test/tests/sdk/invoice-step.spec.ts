import { hexToBytes } from "@noble/hashes/utils.js";
import type { InvoiceAttribute, UnsignedInvoice } from "../../../src/invoice";
import { InvoiceError, encodeInvoice } from "../../../src/invoice";
import type { HoldInvoiceErrorCode, HoldInvoiceReleaseTiming } from "../../../src/policy";
import { HoldInvoiceError, PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError } from "../../../src/rpc";
import type { SdkEvent } from "../../../src/sdk";
import { ActivityTracker, buildInvoiceStep } from "../../../src/sdk";
import { HoldInvoicePreimages } from "../../../src/signer";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { signInvoice } from "../../utils/invoice-signing";
import { rejection } from "../../utils/rejection";
import type { StepRun } from "../../utils/step-run";
import { live, pollFailedEvent, summarized, writesOf } from "../../utils/step-run";

const URL = "http://127.0.0.1:8227";
const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const MASTER_SEED = new Uint8Array(32).fill(0x24);
const PAYEE_SECRET_KEY = new Uint8Array(32).fill(0x11);
const RELEASE_MS_PER_EPOCH = 14_400_000;
const DEBUG_MS_PER_EPOCH = 2_000;
const ONE_EPOCH = 0x10000000001n;
const AMOUNT = "2250000000";
// The preimages of the master seed above at these indexes, and their ckb-hash.
const INDEX = 1_790_812_800_000;
const PREIMAGE = "589281014ba31c52f0dd36c0552a67bd66ef469941eb90fc61d27d8338c00269";
const HASH = "a374e42b6c28035e0c317346d635cc2a93a9b7920e88bd5b0abc96dc23bffc2f";
const OTHER_INDEX = 1_790_812_800_001;
const OTHER_PREIMAGE = "83d906bc11036b868aa2dbb0b2e7fb12436c9fc1612ebf14e522c112ff0c442b";
const OTHER_HASH = "18206fe2a130aa53b64b5e66f6c9d149d4a27de88520da4329ae9c1725f99da9";
const STRANGER_HASH = "5a".repeat(32);
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const TIMESTAMP_MS = 1_790_900_000_000n;
// The timestamp plus the hour of its expiry: fiber's `is_expired` holds only past it.
const EXPIRES_AT_MS = 1_790_903_600_000;
const NOW_MS = 1_790_900_060_000;
const ALREADY_PAID = "Invoice is already paid";

type Harness = {
    node: ScriptedNode;
    storage: InMemorySignerStorage;
    policy: PolicyEngine;
    activity: ActivityTracker;
    events: SdkEvent[];
    pollNow: jest.Mock;
    clock: { nowMs: number };
    step: (run: StepRun) => Promise<void>;
};

function harness(onEmit: (event: SdkEvent) => void = () => undefined, millisecondsPerEpoch = RELEASE_MS_PER_EPOCH): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store);
    const activity = new ActivityTracker(store);
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const pollNow = jest.fn();
    const clock = { nowMs: NOW_MS };
    const step = buildInvoiceStep({
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        policy,
        preimages: new HoldInvoicePreimages(MASTER_SEED),
        activity,
        millisecondsPerEpoch,
        now: () => clock.nowMs,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
        pollNow,
    });
    return { node, storage, policy, activity, events, pollNow, clock, step };
}

async function watching(h: Harness, paymentHash: string, invoiceIndex: number): Promise<void> {
    await h.policy.recordHoldInvoice(paymentHash, AMOUNT, "ckb-hash", invoiceIndex);
    await h.activity.watch("invoice", paymentHash);
}

// The record as policy writes it once released.
async function watchingReleased(h: Harness, paymentHash: string, invoiceIndex: number): Promise<void> {
    h.storage.map.set(
        `fiber-lsp-sdk:invoice:${paymentHash.slice(0, 40)}`,
        JSON.stringify({
            version: 1,
            paymentHash,
            amountShannons: AMOUNT,
            hashAlgorithm: "ckb-hash",
            invoiceIndex,
            released: true,
            channelIndexes: [],
        }),
    );
    await h.activity.watch("invoice", paymentHash);
}

async function invoicesOf(h: Harness): Promise<Record<string, { status: string | null }>> {
    return (await h.activity.read()).invoices;
}

async function releasedOf(h: Harness, paymentHash: string): Promise<boolean> {
    return (await h.policy.readHoldInvoice(paymentHash)).released;
}

function invoiceString(paymentHash: string, attributes: InvoiceAttribute[]): string {
    const unsigned: UnsignedInvoice = {
        currency: "Fibt",
        amountShannons: AMOUNT,
        timestampMs: TIMESTAMP_MS,
        paymentHash: hexToBytes(paymentHash),
        attributes,
    };
    return encodeInvoice(signInvoice(unsigned, PAYEE_SECRET_KEY));
}

function invoiceOf(paymentHash: string): string {
    return invoiceString(paymentHash, [
        { type: "expiryTime", seconds: 3600n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
    ]);
}

function invoiceResult(paymentHash: string, status: string): unknown {
    return { invoice_address: invoiceOf(paymentHash), status };
}

function getInvoiceCall(paymentHash: string): SentCall {
    return { method: "get_invoice", params: { payment_hash: `0x${paymentHash}` } };
}

function settleCall(paymentHash: string, preimage: string): SentCall {
    return { method: "settle_invoice", params: { payment_hash: `0x${paymentHash}`, payment_preimage: `0x${preimage}` } };
}

function holdInvoiceError(code: HoldInvoiceErrorCode): HoldInvoiceError {
    return new HoldInvoiceError(code, `the release of ${HASH} waits: ${code}`);
}

function releasing(h: Harness): jest.SpyInstance<Promise<void>, [string, HoldInvoiceReleaseTiming]> {
    return jest.spyOn(h.policy, "markHoldInvoiceReleased").mockResolvedValue(undefined);
}

function refusingRelease(h: Harness, error: unknown): jest.SpyInstance<Promise<void>, [string, HoldInvoiceReleaseTiming]> {
    return jest.spyOn(h.policy, "markHoldInvoiceReleased").mockRejectedValue(error);
}

function timingOf(mark: jest.SpyInstance<Promise<void>, [string, HoldInvoiceReleaseTiming]>): HoldInvoiceReleaseTiming {
    const call = mark.mock.calls[0];
    if (call === undefined) throw new Error("the release was never tried");
    return call[1];
}

describe("buildInvoiceStep", () => {
    describe("nothing watched", () => {
        it("calls nothing when no invoice was ever watched", async () => {
            const h = harness();
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
        });

        it("calls nothing when only channels and payments are watched", async () => {
            const h = harness();
            await h.activity.watch("channel", CHANNEL_ID);
            await h.activity.watch("payment", HASH);
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
        });

        it("calls nothing once the last watched invoice was paid", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
        });
    });

    describe("an open invoice", () => {
        it("emits and writes nothing, and keeps watching it", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.storage.ops.length = 0;
            h.node.result(invoiceResult(HASH, "Open"));
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("tries no release and reads no expiry, even past it", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const mark = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result({ invoice_address: "not an invoice", status: "Open" });
            await h.step(live());
            expect(mark).not.toHaveBeenCalled();
            expect(h.events).toEqual([]);
        });
    });

    describe("a received invoice", () => {
        it("emits PAYMENT_PENDING and records it, then tries the release, which waits while no channel holds it", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
            expect(await releasedOf(h, HASH)).toBe(false);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("emits PAYMENT_PENDING once across ticks, trying the release on each", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const mark = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Received"));
            await h.step(live());
            h.storage.ops.length = 0;
            await h.step(live());
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(writesOf(h)).toEqual([]);
            expect(mark).toHaveBeenCalledTimes(2);
        });

        it("emits, then records, then tries the release", async () => {
            const order: string[] = [];
            const h = harness((event) => order.push(event.type));
            await watching(h, HASH, INDEX);
            const mark = h.activity.mark.bind(h.activity);
            jest.spyOn(h.activity, "mark").mockImplementation(async (...args) => {
                order.push("mark");
                await mark(...args);
            });
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementation(async () => {
                order.push("release");
            });
            h.node
                .onCall("settle_invoice", () => order.push("settle"))
                .result(invoiceResult(HASH, "Received"))
                .result({});
            await h.step(live());
            expect(order).toEqual(["PAYMENT_PENDING", "mark", "release", "settle"]);
        });

        it("releases it, settles it with the preimage of its index, then asks for a tick", async () => {
            const order: string[] = [];
            const h = harness();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementation(async () => {
                order.push("release");
            });
            h.pollNow.mockImplementation(() => order.push("pollNow"));
            h.node
                .onCall("settle_invoice", () => order.push("settle"))
                .result(invoiceResult(HASH, "Received"))
                .result({});
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), settleCall(HASH, PREIMAGE)]);
            expect(order).toEqual(["release", "settle", "pollNow"]);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("settles each invoice with the preimage of its own index", async () => {
            const h = harness();
            await watching(h, OTHER_HASH, OTHER_INDEX);
            await watching(h, HASH, INDEX);
            releasing(h);
            h.node.result(invoiceResult(OTHER_HASH, "Received")).result({}).result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            expect(h.node.calls()).toEqual([
                getInvoiceCall(OTHER_HASH),
                settleCall(OTHER_HASH, OTHER_PREIMAGE),
                getInvoiceCall(HASH),
                settleCall(HASH, PREIMAGE),
            ]);
            expect(h.pollNow).toHaveBeenCalledTimes(2);
        });

        it("hands the release of the watched hash a clock that keeps the host's first reading", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const mark = releasing(h);
            h.clock.nowMs = 1_790_900_123_456;
            h.node.result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            expect(mark).toHaveBeenCalledTimes(1);
            expect(mark.mock.calls[0]?.[0]).toBe(HASH);
            const { now } = timingOf(mark);
            expect(now()).toBe(1_790_900_123_456);
            h.clock.nowMs = 1_790_900_123_457;
            expect(now()).toBe(1_790_900_123_456);
        });

        it("reads the host's clock once on a tick whose release waits past the invoice's expiry", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            let reads = 0;
            const clock = { nowMs: EXPIRES_AT_MS + 1 };
            Object.defineProperty(h.clock, "nowMs", {
                get: () => {
                    reads += 1;
                    return clock.nowMs;
                },
            });
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "PAYMENT_EXPIRED"]);
            expect(reads).toBe(1);
        });

        it.each([
            ["a release build", RELEASE_MS_PER_EPOCH, 10_200_000n],
            ["a debug build", DEBUG_MS_PER_EPOCH, 601_333n],
        ])("hands the release a margin of two thirds of the delay plus ten minutes on %s", async (_, millisecondsPerEpoch, margin) => {
            const h = harness(() => undefined, millisecondsPerEpoch);
            await watching(h, HASH, INDEX);
            const mark = releasing(h);
            h.node.result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            expect(timingOf(mark).releaseMarginMs(ONE_EPOCH)).toBe(margin);
        });

        it("hands the release a margin that follows the channel's delay", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const mark = releasing(h);
            h.node.result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            // Two epochs and a half: 24 000 000 ms, plus the slack.
            expect(timingOf(mark).releaseMarginMs(0x20005000000n)).toBe(24_600_000n);
        });

        it("settles an invoice whose fulfil was applied meanwhile as settled, asking for a tick", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            releasing(h);
            h.node.result(invoiceResult(HASH, "Received")).error(-32000, ALREADY_PAID);
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), settleCall(HASH, PREIMAGE)]);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(h.pollNow).toHaveBeenCalledTimes(1);
        });

        it("reports a settlement refusal that only looks like fiber's already paid as poll_failed, asking for no tick", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            releasing(h);
            const lookalike = { name: "RpcError", code: -32000, message: ALREADY_PAID };
            const settled = jest.spyOn(FiberRpcClient.prototype, "settleInvoice").mockRejectedValue(lookalike);
            h.node.result(invoiceResult(HASH, "Received"));
            let tries: number;
            try {
                await h.step(live());
            } finally {
                tries = settled.mock.calls.length;
                settled.mockRestore();
            }
            expect(tries).toBe(1);
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "ERROR"]);
            expect(h.events[1]).toMatchObject({ error: { code: "poll_failed", cause: lookalike } });
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it.each<[string, (h: Harness, paymentHash: string, invoiceIndex: number) => Promise<void>, boolean]>([
            ["it releases", watching, false],
            ["was released", watchingReleased, true],
        ])(
            "judges no release and sends no preimage of another hash than the one watched, for an invoice %s",
            async (_, watch, released) => {
                const h = harness();
                await watch(h, HASH, OTHER_INDEX);
                const mark = jest.spyOn(h.policy, "markHoldInvoiceReleased");
                h.node.result(invoiceResult(HASH, "Received"));
                await h.step(live());
                expect(mark).not.toHaveBeenCalled();
                expect(await releasedOf(h, HASH)).toBe(released);
                expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
                expect(summarized(h.events)).toStrictEqual([
                    { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                    pollFailedEvent(
                        `the invoice poll of 0x${HASH} failed: the invoice index recorded for 0x${HASH} derives the preimage of 0x${OTHER_HASH}`,
                        expect.any(TypeError),
                    ),
                ]);
                expect(h.pollNow).not.toHaveBeenCalled();
                expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
            },
        );

        it.each<[string, number, string]>([
            ["another message", -32000, "Invoice is still open"],
            ["another code", -32603, ALREADY_PAID],
        ])("reports a settlement refused with %s as poll_failed naming the invoice, asking for no tick", async (_, code, message) => {
            const h = harness();
            await watching(h, HASH, INDEX);
            releasing(h);
            h.node.result(invoiceResult(HASH, "Received")).error(code, message);
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: ${message}`, expect.any(RpcError)),
            ]);
            expect(h.pollNow).not.toHaveBeenCalled();
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });
    });

    describe("a received invoice already released", () => {
        it("settles it again without judging the release or asking for a tick", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            const mark = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.node.result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), settleCall(HASH, PREIMAGE)]);
            expect(mark).not.toHaveBeenCalled();
            expect(h.pollNow).not.toHaveBeenCalled();
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
        });

        it("settles it again on every tick it stays received", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received")).result({}).result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([
                getInvoiceCall(HASH),
                settleCall(HASH, PREIMAGE),
                getInvoiceCall(HASH),
                settleCall(HASH, PREIMAGE),
            ]);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
        });

        it("takes an invoice already paid as settled", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received")).error(-32000, ALREADY_PAID);
            await h.step(live());
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
        });

        it("never ends it unpaid, even past its expiry with no TLC of it left", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            const lists = jest.spyOn(h.policy, "listsHoldInvoiceTlc");
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(lists).not.toHaveBeenCalled();
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("settles again a release a failed settlement left behind", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementationOnce(async () => {
                await watchingReleased(h, HASH, INDEX);
            });
            h.node
                .result(invoiceResult(HASH, "Received"))
                .error(-32000, "internal error")
                .result(invoiceResult(HASH, "Received"))
                .result({});
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([
                getInvoiceCall(HASH),
                settleCall(HASH, PREIMAGE),
                getInvoiceCall(HASH),
                settleCall(HASH, PREIMAGE),
            ]);
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: internal error`, expect.any(RpcError)),
            ]);
        });
    });

    describe("a release that waits", () => {
        it.each<HoldInvoiceErrorCode>(["not_held", "expiry_too_close", "offered_in_flight"])(
            "emits nothing more on %s, settles nothing and tries again on the next tick",
            async (code) => {
                const h = harness();
                await watching(h, HASH, INDEX);
                const mark = refusingRelease(h, holdInvoiceError(code));
                h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Received"));
                await h.step(live());
                await h.step(live());
                expect(h.node.calls()).toEqual([getInvoiceCall(HASH), getInvoiceCall(HASH)]);
                expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
                expect(mark).toHaveBeenCalledTimes(2);
                expect(h.pollNow).not.toHaveBeenCalled();
                expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
            },
        );

        it("reports algorithm_mismatch as poll_failed naming the invoice, the policy's error its cause", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const error = holdInvoiceError("algorithm_mismatch");
            refusingRelease(h, error);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: ${error.message}`, error),
            ]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("reports a refusal that only looks like a wait as poll_failed, ending nothing", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const lookalike = { name: "HoldInvoiceError", code: "not_held", message: `the release of ${HASH} waits: not_held` };
            refusingRelease(h, lookalike);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "ERROR"]);
            expect(h.events[1]).toMatchObject({ error: { code: "poll_failed", cause: lookalike } });
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("reports a release that fails otherwise as poll_failed naming the invoice", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const error = new TypeError("storage is full");
            refusingRelease(h, error);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: storage is full`, error),
            ]);
        });

        it("reports a host clock the release refuses as poll_failed naming the invoice", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.clock.nowMs = 1.5;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(
                    `the invoice poll of 0x${HASH} failed: timing.now() must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}, got 1.5`,
                    expect.any(RangeError),
                ),
            ]);
        });
    });

    describe("a received invoice that ended unpaid", () => {
        it("emits PAYMENT_EXPIRED past its expiry with no TLC of it left, then stops watching it", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.events).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                { type: "PAYMENT_EXPIRED", paymentHashHex: `0x${HASH}` },
            ]);
            expect(await invoicesOf(h)).toStrictEqual({});
            expect(await releasedOf(h, HASH)).toBe(false);
        });

        it("emits only PAYMENT_EXPIRED for one already announced pending", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Received"));
            await h.step(live());
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            await h.step(live());
            expect(h.events).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                { type: "PAYMENT_EXPIRED", paymentHashHex: `0x${HASH}` },
            ]);
        });

        it.each<HoldInvoiceErrorCode>(["expiry_too_close", "offered_in_flight"])(
            "emits PAYMENT_EXPIRED on %s too, once no TLC of it is left",
            async (code) => {
                const h = harness();
                await watching(h, HASH, INDEX);
                refusingRelease(h, holdInvoiceError(code));
                h.clock.nowMs = EXPIRES_AT_MS + 1;
                h.node.result(invoiceResult(HASH, "Received"));
                await h.step(live());
                expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "PAYMENT_EXPIRED"]);
            },
        );

        it.each<[string, number, number, string[]]>([
            ["at its expiry, though the clock passes it after", EXPIRES_AT_MS, EXPIRES_AT_MS + 1, ["PAYMENT_PENDING"]],
            ["past its expiry, though the clock goes back after", EXPIRES_AT_MS + 1, EXPIRES_AT_MS, ["PAYMENT_PENDING", "PAYMENT_EXPIRED"]],
        ])("judges the expiry against the reading the release took, %s", async (_, read, after, types) => {
            const h = harness();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementation(async (__, timing) => {
                h.clock.nowMs = read;
                timing.now();
                h.clock.nowMs = after;
                throw holdInvoiceError("not_held");
            });
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(types);
        });

        it("emits nothing more at its expiry's exact millisecond, nor reads the channels", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const lists = jest.spyOn(h.policy, "listsHoldInvoiceTlc");
            h.clock.nowMs = EXPIRES_AT_MS;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(lists).not.toHaveBeenCalled();
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("emits nothing more past its expiry while a channel still lists a TLC of it", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const lists = jest.spyOn(h.policy, "listsHoldInvoiceTlc").mockResolvedValue(true);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(lists).toHaveBeenCalledWith(HASH);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("never ends an invoice that carries no expiry", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.clock.nowMs = Number.MAX_SAFE_INTEGER;
            h.node.result({ invoice_address: invoiceString(HASH, [{ type: "hashAlgorithm", algorithm: "ckb-hash" }]), status: "Received" });
            await h.step(live());
            expect(h.events).toStrictEqual([{ type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` }]);
        });

        it("reports a string that is another invoice's as poll_failed naming the invoice, ending nothing", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result({ invoice_address: invoiceOf(STRANGER_HASH), status: "Received" });
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(
                    `the invoice poll of 0x${HASH} failed: the node answered the invoice of 0x${HASH} with that of 0x${STRANGER_HASH}`,
                    expect.any(Error),
                ),
            ]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("reports a string that does not decode as poll_failed naming the invoice, ending nothing", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.node.result({ invoice_address: "fibt1", status: "Received" });
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "ERROR"]);
            expect(h.events[1]).toMatchObject({ error: { code: "poll_failed", cause: expect.any(InvoiceError) } });
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });
    });

    describe("a paid invoice", () => {
        it("emits PAYMENT_RECEIVED for one released, then stops watching it", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_RECEIVED", paymentHashHex: `0x${HASH}` }]);
            expect(await invoicesOf(h)).toStrictEqual({});
        });

        it("reports one never released as poll_failed naming it on every tick, emitting nothing and still watching it", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.storage.ops.length = 0;
            h.node.result(invoiceResult(HASH, "Paid")).result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            await h.step(live());
            const anomaly = pollFailedEvent(
                `the invoice poll of 0x${HASH} failed: the node reports 0x${HASH} paid, but the device never released its preimage`,
                expect.any(Error),
            );
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), getInvoiceCall(HASH)]);
            expect(summarized(h.events)).toStrictEqual([anomaly, anomaly]);
            expect(writesOf(h)).toEqual([]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: null } });
            expect(await releasedOf(h, HASH)).toBe(false);
        });

        it("reports one announced pending but never released as poll_failed, keeping it pending", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "ERROR"]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("reports one with no record as poll_failed naming it", async () => {
            const h = harness();
            await h.activity.watch("invoice", HASH);
            h.node.result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: no hold invoice was recorded for ${HASH}`, expect.any(TypeError)),
            ]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("emits PAYMENT_RECEIVED once the release it judged was settled", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementationOnce(async () => {
                await watchingReleased(h, HASH, INDEX);
            });
            h.node.result(invoiceResult(HASH, "Received")).result({}).result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), settleCall(HASH, PREIMAGE), getInvoiceCall(HASH)]);
            expect(h.events).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                { type: "PAYMENT_RECEIVED", paymentHashHex: `0x${HASH}` },
            ]);
            expect(await invoicesOf(h)).toStrictEqual({});
        });

        it("emits PAYMENT_RECEIVED after PAYMENT_PENDING, settling nothing more", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received")).result({}).result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), settleCall(HASH, PREIMAGE), getInvoiceCall(HASH)]);
            expect(h.events).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                { type: "PAYMENT_RECEIVED", paymentHashHex: `0x${HASH}` },
            ]);
            expect(await invoicesOf(h)).toStrictEqual({});
        });

        it("emits, then stops watching it", async () => {
            const order: string[] = [];
            const h = harness((event) => order.push(event.type));
            await watchingReleased(h, HASH, INDEX);
            const forget = h.activity.forget.bind(h.activity);
            jest.spyOn(h.activity, "forget").mockImplementation(async (...args) => {
                order.push("forget");
                await forget(...args);
            });
            h.node.result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            expect(order).toEqual(["PAYMENT_RECEIVED", "forget"]);
        });
    });

    describe("an invoice fiber ended unpaid", () => {
        it.each(["Expired", "Cancelled"])("emits PAYMENT_EXPIRED for %s, then stops watching it", async (status) => {
            const h = harness();
            await watching(h, HASH, INDEX);
            const mark = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.node.result(invoiceResult(HASH, status));
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.events).toStrictEqual([{ type: "PAYMENT_EXPIRED", paymentHashHex: `0x${HASH}` }]);
            expect(mark).not.toHaveBeenCalled();
            expect(await invoicesOf(h)).toStrictEqual({});
        });

        it("emits PAYMENT_EXPIRED for one announced pending", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Cancelled"));
            await h.step(live());
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "PAYMENT_EXPIRED"]);
        });

        it.each([
            ["Expired", "expired"],
            ["Cancelled", "cancelled"],
        ])("reports %s on one released as poll_failed on every tick, emitting nothing and still watching it", async (status, said) => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.storage.ops.length = 0;
            h.node.result(invoiceResult(HASH, status)).result(invoiceResult(HASH, status));
            await h.step(live());
            await h.step(live());
            const anomaly = pollFailedEvent(
                `the invoice poll of 0x${HASH} failed: the node reports 0x${HASH} ${said}, but the device released its preimage`,
                expect.any(Error),
            );
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), getInvoiceCall(HASH)]);
            expect(summarized(h.events)).toStrictEqual([anomaly, anomaly]);
            expect(writesOf(h)).toEqual([]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: null } });
        });

        it("settles again one released that fiber reports expired, then received", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Expired")).result(invoiceResult(HASH, "Received")).result({});
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), getInvoiceCall(HASH), settleCall(HASH, PREIMAGE)]);
            expect(h.events.map((event) => event.type)).toEqual(["ERROR", "PAYMENT_PENDING"]);
        });
    });

    describe("a failure", () => {
        it("reports an invoice the node cannot answer as poll_failed naming it, then answers the next one", async () => {
            const h = harness();
            await watching(h, OTHER_HASH, OTHER_INDEX);
            await watchingReleased(h, HASH, INDEX);
            h.node.error(-32000, "Invoice not found").result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(OTHER_HASH), getInvoiceCall(HASH)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the invoice poll of 0x${OTHER_HASH} failed: Invoice not found`, expect.any(RpcError)),
                { type: "PAYMENT_RECEIVED", paymentHashHex: `0x${HASH}` },
            ]);
            expect(await invoicesOf(h)).toStrictEqual({ [OTHER_HASH]: { status: null } });
        });

        it("reports a status it does not know as poll_failed naming the invoice", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            h.node.result(invoiceResult(HASH, "Settled"));
            await h.step(live());
            expect(h.events).toHaveLength(1);
            expect(h.events[0]).toMatchObject({ error: { code: "poll_failed", cause: expect.any(RpcResponseError) } });
        });

        it("reports a received invoice with no record as poll_failed naming it", async () => {
            const h = harness();
            await h.activity.watch("invoice", HASH);
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_PENDING", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: no hold invoice was recorded for ${HASH}`, expect.any(TypeError)),
            ]);
        });

        it("rejects the step when the activity list cannot be read, calling nothing", async () => {
            const h = harness();
            h.storage.map.set(ACTIVITY_KEY, "{");
            const error = await rejection(h.step(live()));
            expect(error).toEqual(new TypeError(`stored value at ${ACTIVITY_KEY} is not valid JSON`));
            expect(h.node.calls()).toEqual([]);
        });

        it("emits the event again on the next tick after a forget that failed", async () => {
            const h = harness();
            await watchingReleased(h, HASH, INDEX);
            jest.spyOn(h.activity, "forget").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node.result(invoiceResult(HASH, "Paid")).result(invoiceResult(HASH, "Paid"));
            await h.step(live());
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "PAYMENT_RECEIVED", paymentHashHex: `0x${HASH}` },
                pollFailedEvent(`the invoice poll of 0x${HASH} failed: storage is full`, expect.any(TypeError)),
                { type: "PAYMENT_RECEIVED", paymentHashHex: `0x${HASH}` },
            ]);
            expect(await invoicesOf(h)).toStrictEqual({});
        });

        it("emits PAYMENT_PENDING again on the next tick after a mark that failed, trying no release", async () => {
            const h = harness();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.activity, "mark").mockRejectedValueOnce(new TypeError("storage is full"));
            const release = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Received"));
            await h.step(live());
            expect(release).not.toHaveBeenCalled();
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "ERROR", "PAYMENT_PENDING"]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });
    });

    describe("the host's listener", () => {
        it("keeps answering when it throws", async () => {
            const h = harness(() => {
                throw new Error("the host's listener failed");
            });
            await watching(h, OTHER_HASH, OTHER_INDEX);
            await watchingReleased(h, HASH, INDEX);
            releasing(h);
            h.node.result(invoiceResult(OTHER_HASH, "Received")).result({}).result(invoiceResult(HASH, "Paid"));
            await expect(h.step(live())).resolves.toBeUndefined();
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "PAYMENT_RECEIVED"]);
            expect(h.node.calls()).toEqual([getInvoiceCall(OTHER_HASH), settleCall(OTHER_HASH, OTHER_PREIMAGE), getInvoiceCall(HASH)]);
            expect(h.pollNow).toHaveBeenCalledTimes(1);
            expect(await invoicesOf(h)).toStrictEqual({ [OTHER_HASH]: { status: "Received" } });
        });
    });

    describe("an abandoned run", () => {
        it("emits and records nothing, and answers no further invoice, once abandoned during get_invoice", async () => {
            const h = harness();
            const run = live();
            await watching(h, HASH, INDEX);
            await watching(h, OTHER_HASH, OTHER_INDEX);
            const release = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.storage.ops.length = 0;
            h.node.onCall("get_invoice", () => (run.abandoned = true)).result(invoiceResult(HASH, "Received"));
            await h.step(run);
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
            expect(release).not.toHaveBeenCalled();
        });

        it("records nothing and releases nothing once abandoned by PAYMENT_PENDING, and emits it again on the next tick", async () => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watching(h, HASH, INDEX);
            const release = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.storage.ops.length = 0;
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Received"));
            await h.step(run);
            expect(writesOf(h)).toEqual([]);
            expect(release).not.toHaveBeenCalled();
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "PAYMENT_PENDING"]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });

        it("releases nothing once abandoned while the record is read", async () => {
            const h = harness();
            const run = live();
            await watching(h, HASH, INDEX);
            const read = h.policy.readHoldInvoice.bind(h.policy);
            jest.spyOn(h.policy, "readHoldInvoice").mockImplementationOnce(async (paymentHash) => {
                const record = await read(paymentHash);
                run.abandoned = true;
                return record;
            });
            const release = jest.spyOn(h.policy, "markHoldInvoiceReleased");
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(run);
            expect(release).not.toHaveBeenCalled();
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
        });

        it("settles nothing once abandoned while the record is read, though it was released", async () => {
            const h = harness();
            const run = live();
            await watchingReleased(h, HASH, INDEX);
            const read = h.policy.readHoldInvoice.bind(h.policy);
            jest.spyOn(h.policy, "readHoldInvoice").mockImplementationOnce(async (paymentHash) => {
                const record = await read(paymentHash);
                run.abandoned = true;
                return record;
            });
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(run);
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
        });

        it("settles nothing and asks for no tick once abandoned during the release, and settles on the next tick", async () => {
            const h = harness();
            const run = live();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementationOnce(async () => {
                await watchingReleased(h, HASH, INDEX);
                run.abandoned = true;
            });
            h.node.result(invoiceResult(HASH, "Received")).result(invoiceResult(HASH, "Received")).result({});
            await h.step(run);
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH)]);
            expect(h.pollNow).not.toHaveBeenCalled();
            await h.step(live());
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), getInvoiceCall(HASH), settleCall(HASH, PREIMAGE)]);
        });

        it("asks for no tick once abandoned during settle_invoice, the settlement sent", async () => {
            const h = harness();
            const run = live();
            await watching(h, HASH, INDEX);
            jest.spyOn(h.policy, "markHoldInvoiceReleased").mockImplementationOnce(async () => {
                await watchingReleased(h, HASH, INDEX);
            });
            h.node
                .onCall("settle_invoice", () => (run.abandoned = true))
                .result(invoiceResult(HASH, "Received"))
                .result({});
            await h.step(run);
            expect(h.node.calls()).toEqual([getInvoiceCall(HASH), settleCall(HASH, PREIMAGE)]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it.each<[string, string, (h: Harness, paymentHash: string, invoiceIndex: number) => Promise<void>]>([
            ["PAYMENT_RECEIVED", "Paid", watchingReleased],
            ["PAYMENT_EXPIRED", "Expired", watching],
        ])("keeps watching once abandoned by %s, and emits it again on the next tick", async (type, status, watch) => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watch(h, HASH, INDEX);
            h.storage.ops.length = 0;
            h.node.result(invoiceResult(HASH, status)).result(invoiceResult(HASH, status));
            await h.step(run);
            expect(writesOf(h)).toEqual([]);
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual([type, type]);
            expect(await invoicesOf(h)).toStrictEqual({});
        });

        it("keeps watching once abandoned by PAYMENT_EXPIRED of a received invoice", async () => {
            const run = live();
            const h = harness((event) => {
                if (event.type === "PAYMENT_EXPIRED") run.abandoned = true;
            });
            await watching(h, HASH, INDEX);
            h.clock.nowMs = EXPIRES_AT_MS + 1;
            h.node.result(invoiceResult(HASH, "Received"));
            await h.step(run);
            expect(h.events.map((event) => event.type)).toEqual(["PAYMENT_PENDING", "PAYMENT_EXPIRED"]);
            expect(await invoicesOf(h)).toStrictEqual({ [HASH]: { status: "Received" } });
        });
    });
});
