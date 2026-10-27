import { SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkEvent } from "../../../src/sdk";
import { ActivityTracker, PendingOpeningStore, SdkError, buildChannelStep } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import { LIST_CHANNELS_WITH_CLOSED_CALL } from "../../utils/rpc-answers";
import type { StepRun } from "../../utils/step-run";
import { live, pollFailedEvent, summarized } from "../../utils/step-run";

const URL = "http://127.0.0.1:8227";
const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const OPENING_KEY = "fiber-lsp-sdk:opening";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_ID = `0x${"2e".repeat(32)}`;
const UNWATCHED_ID = `0x${"5a".repeat(32)}`;
const PAYMENT_HASH = "ab".repeat(32);
const LOCK = { codeHash: new Uint8Array(32).fill(0x9b), hashType: "type", args: new Uint8Array(20).fill(0x11) } as const;
const ONLY_PENDING_CALL: SentCall = { method: "list_channels", params: { only_pending: true } };
const READY = { state_name: "ChannelReady" };
const AWAITING_READY = { state_name: "AwaitingChannelReady", state_flags: "OUR_CHANNEL_READY" };
const ABORTED = { state_name: "Closed", state_flags: "FUNDING_ABORTED" };
const COOPERATIVE = { state_name: "Closed", state_flags: "COOPERATIVE" };

type Harness = {
    node: ScriptedNode;
    storage: InMemorySignerStorage;
    activity: ActivityTracker;
    openings: PendingOpeningStore;
    events: SdkEvent[];
    step: (run: StepRun) => Promise<void>;
};

function harness(onEmit: (event: SdkEvent) => void = () => undefined): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const activity = new ActivityTracker(store);
    const openings = new PendingOpeningStore(store);
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const step = buildChannelStep({
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        activity,
        openings,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
    });
    return { node, storage, activity, openings, events, step };
}

async function watching(h: Harness, ...channelIds: string[]): Promise<void> {
    for (const channelId of channelIds) await h.activity.watch("channel", channelId);
}

async function pendingFor(h: Harness, channelId: string): Promise<void> {
    await h.openings.write(1_790_812_800, "10000000000", LOCK);
    await h.openings.setChannelId(1_790_812_800, channelId);
}

async function channelsOf(h: Harness): Promise<Record<string, { status: string | null }>> {
    return (await h.activity.read()).channels;
}

function writesOf(h: Harness): string[] {
    return h.storage.ops.filter((op) => op.startsWith("set "));
}

function listing(...channels: [string, unknown][]): unknown {
    return { channels: channels.map(([channelId, state]) => ({ channel_id: channelId, state })) };
}

describe("buildChannelStep", () => {
    describe("nothing watched", () => {
        it("calls nothing when no channel was ever watched", async () => {
            const h = harness();
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
        });

        it("calls nothing when only payments and invoices are watched", async () => {
            const h = harness();
            await h.activity.watch("payment", PAYMENT_HASH);
            await h.activity.watch("invoice", PAYMENT_HASH);
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
        });

        it("calls nothing once the last watched channel closed", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, COOPERATIVE]));
            await h.step(live());
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
        });
    });

    describe("a channel turning ready", () => {
        it("emits CHANNEL_READY, then records it, once", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, READY]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toStrictEqual([{ type: "CHANNEL_READY", channelId: CHANNEL_ID }]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: "ChannelReady" } });
        });

        it("emits nothing and writes nothing when the channel is still ready", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, READY])).result(listing([CHANNEL_ID, READY]));
            await h.step(live());
            h.storage.ops.length = 0;
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toStrictEqual([{ type: "CHANNEL_READY", channelId: CHANNEL_ID }]);
            expect(writesOf(h)).toEqual([]);
        });

        it("emits, then drops its pending opening, then records it", async () => {
            const order: string[] = [];
            const h = harness((event) => order.push(event.type));
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            const clear = h.openings.clear.bind(h.openings);
            jest.spyOn(h.openings, "clear").mockImplementation(async (channelId) => {
                order.push("clear");
                return clear(channelId);
            });
            const mark = h.activity.mark.bind(h.activity);
            jest.spyOn(h.activity, "mark").mockImplementation(async (...args) => {
                order.push("mark");
                await mark(...args);
            });
            h.node.result(listing([CHANNEL_ID, READY]));
            await h.step(live());
            expect(order).toEqual(["CHANNEL_READY", "clear", "mark"]);
            await expect(h.openings.read()).resolves.toBeNull();
        });
    });

    describe("a channel that closed", () => {
        it.each([
            "COOPERATIVE",
            "UNCOOPERATIVE_LOCAL",
            "UNCOOPERATIVE_REMOTE",
            "ABANDONED",
            "FUNDING_ABORTED",
            "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT",
        ])("emits CHANNEL_CLOSED for %s, then stops watching it", async (flags) => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, { state_name: "Closed", state_flags: flags }]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toStrictEqual([{ type: "CHANNEL_CLOSED", channelId: CHANNEL_ID }]);
            expect(await channelsOf(h)).toStrictEqual({});
        });

        it("emits CHANNEL_CLOSED for a channel that was ready", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, READY])).result(listing([CHANNEL_ID, COOPERATIVE]));
            await h.step(live());
            await h.step(live());
            expect(h.events).toStrictEqual([
                { type: "CHANNEL_READY", channelId: CHANNEL_ID },
                { type: "CHANNEL_CLOSED", channelId: CHANNEL_ID },
            ]);
            expect(await channelsOf(h)).toStrictEqual({});
        });

        it("emits, then drops its pending opening, then stops watching it", async () => {
            const order: string[] = [];
            const h = harness((event) => order.push(event.type));
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            const clear = h.openings.clear.bind(h.openings);
            jest.spyOn(h.openings, "clear").mockImplementation(async (channelId) => {
                order.push("clear");
                return clear(channelId);
            });
            const forget = h.activity.forget.bind(h.activity);
            jest.spyOn(h.activity, "forget").mockImplementation(async (...args) => {
                order.push("forget");
                await forget(...args);
            });
            h.node.result(listing([CHANNEL_ID, ABORTED]));
            await h.step(live());
            expect(order).toEqual(["CHANNEL_CLOSED", "clear", "forget"]);
            await expect(h.openings.read()).resolves.toBeNull();
        });
    });

    describe("a channel in any other state", () => {
        it.each<[string, unknown]>([
            ["NegotiatingFunding", { state_name: "NegotiatingFunding", state_flags: "AWAITING_EXTERNAL_FUNDING" }],
            ["CollaboratingFundingTx", { state_name: "CollaboratingFundingTx", state_flags: "AWAITING_REMOTE_TX_COLLABORATION_MSG" }],
            ["SigningCommitment", { state_name: "SigningCommitment", state_flags: "OUR_COMMITMENT_SIGNED_SENT" }],
            ["AwaitingTxSignatures", { state_name: "AwaitingTxSignatures", state_flags: "OUR_TX_SIGNATURES_SENT" }],
            ["AwaitingChannelReady", AWAITING_READY],
            ["ShuttingDown", { state_name: "ShuttingDown", state_flags: "OUR_SHUTDOWN_SENT" }],
            ["Stale", { state_name: "Stale" }],
            ["a state fiber may add", { state_name: "Splicing", state_flags: "SPLICE_SENT" }],
        ])("emits and writes nothing for %s, and keeps watching it", async (_, state) => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            h.node.result(listing([CHANNEL_ID, state]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: null } });
        });

        it("emits nothing for a ready channel that is shutting down", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node
                .result(listing([CHANNEL_ID, READY]))
                .result(listing([CHANNEL_ID, { state_name: "ShuttingDown", state_flags: "OUR_SHUTDOWN_SENT" }]));
            await h.step(live());
            await h.step(live());
            expect(h.events).toStrictEqual([{ type: "CHANNEL_READY", channelId: CHANNEL_ID }]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: "ChannelReady" } });
        });
    });

    describe("a channel the listing leaves out", () => {
        it("reads the pending channels and emits CHANNEL_CLOSED for an opening fiber aborted", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            h.node.result(listing()).result(listing([CHANNEL_ID, ABORTED]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, ONLY_PENDING_CALL]);
            expect(h.events).toStrictEqual([{ type: "CHANNEL_CLOSED", channelId: CHANNEL_ID }]);
            expect(await channelsOf(h)).toStrictEqual({});
            await expect(h.openings.read()).resolves.toBeNull();
        });

        it("reads the pending channels once for every channel left out, after settling the listed ones", async () => {
            const h = harness();
            const third = `0x${"3d".repeat(32)}`;
            await watching(h, CHANNEL_ID, OTHER_ID, third);
            h.node.result(listing([third, READY])).result(listing([OTHER_ID, ABORTED], [CHANNEL_ID, ABORTED]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, ONLY_PENDING_CALL]);
            expect(h.events).toStrictEqual([
                { type: "CHANNEL_READY", channelId: third },
                { type: "CHANNEL_CLOSED", channelId: OTHER_ID },
                { type: "CHANNEL_CLOSED", channelId: CHANNEL_ID },
            ]);
            expect(await channelsOf(h)).toStrictEqual({ [third]: { status: "ChannelReady" } });
        });

        it("settles a pending channel that is still opening as it would a listed one", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.node.result(listing()).result(listing([CHANNEL_ID, AWAITING_READY]));
            await h.step(live());
            expect(h.events).toEqual([]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: null } });
        });

        it("keeps watching a channel neither listing shows, emitting nothing", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            h.node.result(listing([UNWATCHED_ID, READY])).result(listing([UNWATCHED_ID, ABORTED]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, ONLY_PENDING_CALL]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
        });

        it("reads no pending channels when every watched channel is listed", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID, OTHER_ID);
            h.node.result(listing([OTHER_ID, AWAITING_READY], [CHANNEL_ID, AWAITING_READY]));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
        });

        it("settles a watched channel the pending listing shows only once, when the first listing already had it", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID, OTHER_ID);
            h.node.result(listing([CHANNEL_ID, READY])).result(listing([CHANNEL_ID, READY], [OTHER_ID, ABORTED]));
            await h.step(live());
            expect(h.events).toStrictEqual([
                { type: "CHANNEL_READY", channelId: CHANNEL_ID },
                { type: "CHANNEL_CLOSED", channelId: OTHER_ID },
            ]);
        });
    });

    describe("channels nobody watches", () => {
        it("ignores them in both listings", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            h.node.result(listing([UNWATCHED_ID, READY], [OTHER_ID, COOPERATIVE])).result(listing([UNWATCHED_ID, ABORTED]));
            await h.step(live());
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: null } });
        });
    });

    describe("the pending opening", () => {
        it.each<[string, unknown]>([
            ["ready", READY],
            ["closed", COOPERATIVE],
        ])("is kept when another channel turns %s", async (_, state) => {
            const h = harness();
            await watching(h, CHANNEL_ID, OTHER_ID);
            await pendingFor(h, CHANNEL_ID);
            h.node.result(listing([OTHER_ID, state], [CHANNEL_ID, AWAITING_READY]));
            await h.step(live());
            await expect(h.openings.read()).resolves.toMatchObject({ channelId: CHANNEL_ID });
        });

        it("is kept when its channel is listed in any other state", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, AWAITING_READY]));
            await h.step(live());
            await expect(h.openings.read()).resolves.toMatchObject({ channelId: CHANNEL_ID });
        });

        it("is kept while it names no channel yet", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            await h.openings.write(1_790_812_800, "10000000000", LOCK);
            h.node.result(listing([CHANNEL_ID, READY]));
            await h.step(live());
            await expect(h.openings.read()).resolves.toMatchObject({ channelId: null });
        });
    });

    describe("a failure", () => {
        it.each<[string, (node: ScriptedNode) => void, unknown, string]>([
            ["refuses", (node) => node.error(-32000, "internal error"), RpcError, "internal error"],
            [
                "cannot be reached",
                (node) => node.reject(new TypeError("fetch failed")),
                RpcTransportError,
                "list_channels: the request failed",
            ],
            [
                "answers with a channel it cannot read",
                (node) => node.result({ channels: [{ channel_id: CHANNEL_ID }] }),
                RpcResponseError,
                "list_channels: response.result.channels[0].state must be an object",
            ],
        ])("rejects the step when the listing %s, emitting and writing nothing", async (_, fail, type, message) => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            fail(h.node);
            const error = await rejection(h.step(live()));
            expect(error).toBeInstanceOf(type);
            expect((error as Error).message).toBe(message);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
        });

        it("rejects the step when the pending listing fails, the listed channels already settled", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID, OTHER_ID);
            h.node.result(listing([CHANNEL_ID, READY])).error(-32000, "internal error");
            const error = await rejection(h.step(live()));
            expect(error).toBeInstanceOf(RpcError);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, ONLY_PENDING_CALL]);
            expect(h.events).toStrictEqual([{ type: "CHANNEL_READY", channelId: CHANNEL_ID }]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: "ChannelReady" }, [OTHER_ID]: { status: null } });
        });

        it("rejects the step when the activity list cannot be read, calling nothing", async () => {
            const h = harness();
            h.storage.map.set(ACTIVITY_KEY, "{");
            const error = await rejection(h.step(live()));
            expect(error).toEqual(new TypeError(`stored value at ${ACTIVITY_KEY} is not valid JSON`));
            expect(h.node.calls()).toEqual([]);
        });

        it("reports a mark that fails as poll_failed naming the channel, then settles the next one", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID, OTHER_ID);
            jest.spyOn(h.activity, "mark").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node.result(listing([CHANNEL_ID, READY], [OTHER_ID, COOPERATIVE]));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "CHANNEL_READY", channelId: CHANNEL_ID },
                pollFailedEvent(`the channel poll of ${CHANNEL_ID} failed: storage is full`, expect.any(TypeError)),
                { type: "CHANNEL_CLOSED", channelId: OTHER_ID },
            ]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: null } });
        });

        it("emits the event again on the next tick after a mark that failed", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            jest.spyOn(h.activity, "mark").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node.result(listing([CHANNEL_ID, READY])).result(listing([CHANNEL_ID, READY]));
            await h.step(live());
            await h.step(live());
            expect(h.events.map((event) => event.type)).toEqual(["CHANNEL_READY", "ERROR", "CHANNEL_READY"]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: "ChannelReady" } });
        });

        it("reports a pending opening it cannot read as poll_failed naming the channel, recording nothing", async () => {
            const h = harness();
            await watching(h, CHANNEL_ID);
            h.storage.map.set(OPENING_KEY, '{"version":2,"opening":null}');
            h.node.result(listing([CHANNEL_ID, COOPERATIVE]));
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                { type: "CHANNEL_CLOSED", channelId: CHANNEL_ID },
                pollFailedEvent(
                    `the channel poll of ${CHANNEL_ID} failed: stored value at ${OPENING_KEY} is not a pending opening record`,
                    expect.any(TypeError),
                ),
            ]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: null } });
        });
    });

    describe("the host's listener", () => {
        it("keeps settling when it throws", async () => {
            const h = harness(() => {
                throw new Error("the host's listener failed");
            });
            await watching(h, CHANNEL_ID, OTHER_ID);
            await pendingFor(h, CHANNEL_ID);
            h.node.result(listing([CHANNEL_ID, READY], [OTHER_ID, COOPERATIVE]));
            await expect(h.step(live())).resolves.toBeUndefined();
            expect(h.events.map((event) => event.type)).toEqual(["CHANNEL_READY", "CHANNEL_CLOSED"]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: "ChannelReady" } });
            await expect(h.openings.read()).resolves.toBeNull();
        });
    });

    describe("an abandoned run", () => {
        it("emits and records nothing, and reads no pending channels, once abandoned during the listing", async () => {
            const h = harness();
            const run = live();
            await watching(h, CHANNEL_ID, OTHER_ID);
            h.storage.ops.length = 0;
            h.node.onCall("list_channels", () => (run.abandoned = true)).result(listing([CHANNEL_ID, READY]));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
        });

        it("emits nothing once abandoned during the pending listing", async () => {
            const h = harness();
            const run = live();
            await watching(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            h.node
                .onCall("list_channels", () => h.node.onCall("list_channels", () => (run.abandoned = true)))
                .result(listing())
                .result(listing([CHANNEL_ID, ABORTED]));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, ONLY_PENDING_CALL]);
            expect(h.events).toEqual([]);
            expect(writesOf(h)).toEqual([]);
        });

        it("records nothing once abandoned by its own event, and emits it again on the next tick", async () => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            h.node.result(listing([CHANNEL_ID, READY], [OTHER_ID, READY])).result(listing([CHANNEL_ID, READY]));
            await h.step(run);
            expect(h.events).toStrictEqual([{ type: "CHANNEL_READY", channelId: CHANNEL_ID }]);
            expect(writesOf(h)).toEqual([]);
            await h.step(live());
            expect(h.events).toStrictEqual([
                { type: "CHANNEL_READY", channelId: CHANNEL_ID },
                { type: "CHANNEL_READY", channelId: CHANNEL_ID },
            ]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: "ChannelReady" } });
            await expect(h.openings.read()).resolves.toBeNull();
        });

        it("keeps watching a closed channel once abandoned by its own event, and emits it again on the next tick", async () => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watching(h, CHANNEL_ID);
            await pendingFor(h, CHANNEL_ID);
            h.storage.ops.length = 0;
            h.node.result(listing([CHANNEL_ID, COOPERATIVE])).result(listing([CHANNEL_ID, COOPERATIVE]));
            await h.step(run);
            expect(writesOf(h)).toEqual([]);
            expect(await channelsOf(h)).toStrictEqual({ [CHANNEL_ID]: { status: null } });
            await h.step(live());
            expect(h.events).toStrictEqual([
                { type: "CHANNEL_CLOSED", channelId: CHANNEL_ID },
                { type: "CHANNEL_CLOSED", channelId: CHANNEL_ID },
            ]);
            expect(await channelsOf(h)).toStrictEqual({});
            await expect(h.openings.read()).resolves.toBeNull();
        });

        it("reads no pending channels once abandoned while settling the listed ones", async () => {
            const run = live();
            const h = harness(() => (run.abandoned = true));
            await watching(h, CHANNEL_ID, OTHER_ID);
            h.node.result(listing([CHANNEL_ID, READY]));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
        });
    });

    it("reports poll_failed errors as SdkError", async () => {
        const h = harness();
        await watching(h, CHANNEL_ID);
        jest.spyOn(h.activity, "forget").mockRejectedValueOnce(new TypeError("storage is full"));
        h.node.result(listing([CHANNEL_ID, COOPERATIVE]));
        await h.step(live());
        expect(h.events[1]).toMatchObject({ type: "ERROR", error: expect.any(SdkError) });
    });
});
