import type { PolicyEngineOptions } from "../../../src/policy";
import { CHANNEL_ALIAS_KEY_PREFIX, CHANNEL_RECORD_KEY_PREFIX } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkEvent } from "../../../src/sdk";
import { ActivityTracker, DeviceChannelList, SdkError, buildWatchtowerSigningStep } from "../../../src/sdk";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { watchtowerStatusCall } from "../../utils/rpc-answers";
import type { SigningChannel } from "../../utils/signing-channel";
import { openWatchtowerChannel } from "../../utils/signing-channel";
import type { SigningWatchtowerSpendVector } from "../../utils/signing-vectors";
import {
    loadSigningVectors,
    toWatchtowerKeyPurpose,
    watchtowerApprovalOf,
    watchtowerSpendOf,
    watchtowerStatusField,
    watchtowerVariantOf,
} from "../../utils/signing-vectors";
import { abandonAfterHandleWatchtower, live, pollFailedEvent, summarized } from "../../utils/step-run";
import { withField } from "../../utils/with-field";
import { storedAt, writes } from "../../utils/stored-records";

const vectors = loadSigningVectors();
// Registered on an index with no record: polled, and idle wherever it is listed.
const OTHER_ID = `0x${"2e".repeat(32)}`;
const OTHER_INDEX = 7;
const UNREGISTERED_ID = `0x${"5a".repeat(32)}`;
const URL = "http://127.0.0.1:8227";
const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const DEVICE_CHANNELS_KEY = "fiber-lsp-sdk:device-channels";
const IDLE = { type: "NoSignatureRequired" };
const UNWATCHED = "watched channel not found";
const APPLIED = { type: "Applied" };
const ALREADY_APPLIED = { type: "AlreadyApplied" };
const APPROVAL = watchtowerApprovalOf(vectors);
const DEVICE_SPENDS = vectors.watchtower.views.flatMap((view) => view.spends);
const SETTLEMENT = watchtowerSpendOf(vectors, "own commitment: settlement");
const INBOUND_TLC = watchtowerSpendOf(vectors, "peer's commitment: inbound TLC by preimage");
const OUTBOUND_TLC = watchtowerSpendOf(vectors, "own commitment: outbound TLC by timeout");

type Harness = {
    channel: SigningChannel;
    activity: ActivityTracker;
    channels: DeviceChannelList;
    node: ScriptedNode;
    events: SdkEvent[];
    step: (run: { abandoned: boolean }) => Promise<void>;
};

async function harness(
    options: PolicyEngineOptions = { watchtower: APPROVAL },
    onEmit: (event: SdkEvent) => void = () => undefined,
): Promise<Harness> {
    const channel = await openWatchtowerChannel(vectors, options);
    await channel.store.claimChannelAlias(OTHER_ID, OTHER_INDEX);
    const activity = new ActivityTracker(channel.store);
    const channels = new DeviceChannelList(channel.store);
    await activity.watch("channel", channel.channelId);
    await channels.add(channel.channelId);
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const step = buildWatchtowerSigningStep({
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        store: channel.store,
        policy: channel.policy,
        dispatch: channel.dispatch,
        activity,
        channels,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
    });
    return { channel, activity, channels, node, events, step };
}

// The channels the device opened, in that order, each open (watched by the activity) or seen closed.
async function polling(h: Harness, listed: readonly (readonly [string, boolean])[]): Promise<void> {
    const id = h.channel.channelId;
    await h.channels.remove(id);
    await h.activity.forget("channel", id);
    for (const [channelId, open] of listed) {
        if (open) await h.activity.watch("channel", channelId);
        await h.channels.add(channelId);
    }
}

function channelIdOf(h: Harness): string {
    return h.channel.channelId;
}

function statusResult(channelId: string, status: unknown): unknown {
    return { channel_id: channelId, status: structuredClone(status) };
}

function spendResult(channelId: string, spend: SigningWatchtowerSpendVector): unknown {
    return statusResult(channelId, watchtowerStatusField(spend).value);
}

function submissionCall(channelId: string, spend: SigningWatchtowerSpendVector): SentCall {
    return {
        method: "submit_watchtower_signature",
        params: { channel_id: channelId, request_id: spend.request_id, signature: spend.signature },
    };
}

async function appliedOf(h: Harness): Promise<[string, boolean][]> {
    const record = await h.channel.store.getChannelRecord(h.channel.channelIndex);
    return (record?.watchtowerSpends ?? []).map((spend) => [`0x${spend.requestId}`, spend.applied]);
}

function markWrite(h: Harness): string[] {
    return [`${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex}`];
}

function signedEvent(channelId: string, spend: SigningWatchtowerSpendVector): SdkEvent {
    return {
        type: "WATCHTOWER_SIGNING",
        channelId,
        requestId: spend.request_id,
        purpose: toWatchtowerKeyPurpose(spend.key_purpose),
        outcome: "signed",
    };
}

describe("buildWatchtowerSigningStep", () => {
    describe("a spend the device signs", () => {
        it.each(DEVICE_SPENDS.map((spend) => [spend.name, spend] as const))(
            "submits %s with the vectors' signature, marks it applied, then emits it signed",
            async (_, spend) => {
                const h = await harness();
                const id = channelIdOf(h);
                h.node.result(spendResult(id, spend)).result(APPLIED);
                await h.step(live());
                expect(h.node.calls()).toEqual([watchtowerStatusCall(id), submissionCall(id, spend)]);
                expect(await appliedOf(h)).toEqual([[spend.request_id, true]]);
                expect(h.events).toStrictEqual([signedEvent(id, spend)]);
            },
        );

        it("marks the spend applied once the node took its signature, before it emits", async () => {
            const order: string[] = [];
            const h = await harness({ watchtower: APPROVAL }, (event) => order.push(event.type));
            const id = channelIdOf(h);
            const mark = h.channel.policy.markWatchtowerSpendApplied.bind(h.channel.policy);
            jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied").mockImplementation(async (...args) => {
                order.push("mark");
                await mark(...args);
            });
            h.node
                .onCall("submit_watchtower_signature", () => order.push("submit"))
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            expect(order).toEqual(["submit", "mark", "WATCHTOWER_SIGNING"]);
        });

        // Fiber keeps the requests a rebuild superseded, and serves the lowest id first: one may come after the spend it signed.
        it("submits a request for the unlock of a spend it signed already, marking nothing, and emits it signed", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            const supersededId = `0x${"0d".repeat(32)}`;
            const mark = jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied");
            h.channel.storage.ops.length = 0;
            h.node.result(statusResult(id, withField(watchtowerStatusField(SETTLEMENT).value, "request_id", supersededId))).result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(2)).toEqual([
                watchtowerStatusCall(id),
                {
                    method: "submit_watchtower_signature",
                    params: { channel_id: id, request_id: supersededId, signature: SETTLEMENT.signature },
                },
            ]);
            expect(mark).not.toHaveBeenCalled();
            expect(writes(h.channel.storage)).toEqual([]);
            expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, true]]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT), { ...signedEvent(id, SETTLEMENT), requestId: supersededId }]);
        });

        it("resends an already signed spend with the same bytes, writing nothing, and takes AlreadyApplied as success", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            h.channel.storage.ops.length = 0;
            h.node.result(spendResult(id, SETTLEMENT)).result(ALREADY_APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
            ]);
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT), signedEvent(id, SETTLEMENT)]);
        });

        it("answers every registered channel the device lists, in the order it opened them, and no other", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [
                [UNREGISTERED_ID, true],
                [OTHER_ID, true],
                [id, true],
            ]);
            h.node.result(statusResult(OTHER_ID, IDLE)).result(spendResult(id, INBOUND_TLC)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(OTHER_ID), watchtowerStatusCall(id), submissionCall(id, INBOUND_TLC)]);
            expect(h.events).toStrictEqual([signedEvent(id, INBOUND_TLC)]);
        });
    });

    describe("a spend the device refuses", () => {
        it("emits the refusal of a device whose host approved no destination, with its request id and purpose, submitting nothing", async () => {
            const h = await harness({});
            const id = channelIdOf(h);
            h.channel.storage.ops.length = 0;
            h.node.result(spendResult(id, OUTBOUND_TLC));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.events).toStrictEqual([
                {
                    type: "WATCHTOWER_SIGNING",
                    channelId: id,
                    requestId: OUTBOUND_TLC.request_id,
                    purpose: toWatchtowerKeyPurpose(OUTBOUND_TLC.key_purpose),
                    outcome: "refused",
                    error: {
                        code: "policy_refusal",
                        message: "watchtower option: the host approved no destination, so the device signs no watchtower spend",
                    },
                },
            ]);
        });

        it("emits the refusal of a spend a rule refuses, submitting nothing", async () => {
            const variant = watchtowerVariantOf(vectors, "foreign destination");
            const h = await harness();
            const id = channelIdOf(h);
            h.node.result(statusResult(id, watchtowerStatusField(variant).value));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(h.events).toStrictEqual([
                {
                    type: "WATCHTOWER_SIGNING",
                    channelId: id,
                    requestId: variant.request_id,
                    purpose: toWatchtowerKeyPurpose(variant.key_purpose),
                    outcome: "refused",
                    error: {
                        code: "policy_refusal",
                        message: "watchtower destination: output 1 must pay the approved destination, with no type and no data",
                    },
                },
            ]);
        });

        it("emits a status it cannot read as refused, with neither request id nor purpose", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.channel.storage.ops.length = 0;
            const status = withField(watchtowerStatusField(SETTLEMENT).value, "request_id", "0x00");
            h.node.result(statusResult(id, status));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.events).toStrictEqual([
                {
                    type: "WATCHTOWER_SIGNING",
                    channelId: id,
                    requestId: null,
                    purpose: null,
                    outcome: "refused",
                    error: {
                        code: "malformed",
                        message: "response.result.status.request_id must be 32 bytes of 0x-prefixed lowercase hex",
                    },
                },
            ]);
        });

        it("refuses the status of another channel as malformed, without handing it to the dispatch", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const handle = jest.spyOn(h.channel.dispatch, "handleWatchtower");
            h.channel.storage.ops.length = 0;
            h.node.result(spendResult(OTHER_ID, SETTLEMENT));
            await h.step(live());
            expect(handle).not.toHaveBeenCalled();
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(h.events).toStrictEqual([
                {
                    type: "WATCHTOWER_SIGNING",
                    channelId: id,
                    requestId: null,
                    purpose: null,
                    outcome: "refused",
                    error: {
                        code: "malformed",
                        message: `the node answered the watchtower signing status of ${id} with that of ${OTHER_ID}`,
                    },
                },
            ]);
        });

        it("emits the refusal again on every tick the spend stays pending", async () => {
            const h = await harness({});
            const id = channelIdOf(h);
            for (let tick = 0; tick < 2; tick++) {
                h.node.result(spendResult(id, SETTLEMENT));
                await h.step(live());
            }
            expect(h.events.map((event) => (event.type === "WATCHTOWER_SIGNING" ? event.outcome : event.type))).toEqual([
                "refused",
                "refused",
            ]);
        });
    });

    describe("the channels it polls", () => {
        it.each<[string, boolean]>([
            ["open", true],
            ["closed", false],
        ])("polls a channel the device opened, %s, and signs its spend", async (_, open) => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [[id, open]]);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT)]);
            expect(await h.channels.read()).toEqual([id]);
        });

        it("reads no listing of the node's channels: the device's own list alone says which to poll", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node.result(statusResult(id, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
        });

        // Fiber deletes the row on a cooperative close, an abandon or an aborted funding, and never creates one after.
        it("drops a closed channel fiber holds no watch row for, and asks nothing about it again", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [
                [id, false],
                [OTHER_ID, true],
            ]);
            h.node.error(-32000, UNWATCHED).result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(await h.channels.read()).toEqual([OTHER_ID]);
            expect(storedAt(h.channel.storage, DEVICE_CHANNELS_KEY)).toEqual({ version: 1, channelIds: [OTHER_ID] });
            h.node.result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), watchtowerStatusCall(OTHER_ID), watchtowerStatusCall(OTHER_ID)]);
            expect(h.events).toEqual([]);
        });

        it.each<[string, (node: ScriptedNode) => void, string, unknown]>([
            [
                "another message",
                (node) => node.error(-32000, "watched channel not found yet"),
                "watched channel not found yet",
                expect.any(RpcError),
            ],
            ["another code", (node) => node.error(-32603, UNWATCHED), UNWATCHED, expect.any(RpcError)],
            [
                "a failed request",
                (node) => node.reject(new TypeError("fetch failed")),
                "get_watchtower_signing_status: the request failed",
                expect.any(RpcTransportError),
            ],
        ])("keeps a closed channel whose status read fails with %s, reporting it as poll_failed", async (_, fail, message, cause) => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [[id, false]]);
            fail(h.node);
            await h.step(live());
            expect(await h.channels.read()).toEqual([id]);
            expect(summarized(h.events)).toStrictEqual([pollFailedEvent(`the watchtower signing poll of ${id} failed: ${message}`, cause)]);
        });

        // An opening is watched before it is listed: read in the other order, its pins' last two writes could land between the reads.
        it("reads the device's list before the activity: a channel listed while unwatched and watched before the activity read is kept", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [[id, false]]);
            const read = h.channels.read.bind(h.channels);
            jest.spyOn(h.channels, "read").mockImplementationOnce(async () => {
                const listed = await read();
                await h.activity.watch("channel", id);
                return listed;
            });
            h.node.error(-32000, UNWATCHED);
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(await h.channels.read()).toEqual([id]);
            expect(h.events).toEqual([]);
        });

        it("keeps a closed channel fiber stopped watching when the run was abandoned during the read", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [[id, false]]);
            const run = live();
            h.node.onCall("get_watchtower_signing_status", () => (run.abandoned = true)).error(-32000, UNWATCHED);
            await h.step(run);
            expect(await h.channels.read()).toEqual([id]);
        });

        it("reports a drop it cannot write as poll_failed, then answers the next channel", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [
                [id, false],
                [OTHER_ID, true],
            ]);
            jest.spyOn(h.channels, "remove").mockRejectedValueOnce(new Error("storage offline"));
            h.node.error(-32000, UNWATCHED).result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), watchtowerStatusCall(OTHER_ID)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the watchtower signing poll of ${id} failed: storage offline`, expect.any(Error)),
            ]);
        });

        it.each<[string, string]>([
            ["the device's channels", DEVICE_CHANNELS_KEY],
            ["the activity list", ACTIVITY_KEY],
        ])("rejects when %s cannot be read, calling the node for nothing", async (_, key) => {
            const h = await harness();
            h.channel.storage.map.set(key, "garbage");
            await expect(h.step(live())).rejects.toEqual(new TypeError(`stored value at ${key} is not valid JSON`));
            expect(h.node.calls()).toEqual([]);
            expect(h.events).toEqual([]);
        });
    });

    describe("nothing to answer", () => {
        it("reads fiber's answer for an open channel with no watch row yet as nothing pending, keeps it, then answers the next", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [
                [id, true],
                [OTHER_ID, true],
            ]);
            h.node.error(-32000, UNWATCHED).result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), watchtowerStatusCall(OTHER_ID)]);
            expect(await h.channels.read()).toEqual([id, OTHER_ID]);
            expect(h.events).toEqual([]);
        });

        it.each<[string, number, string]>([
            ["another message", -32000, "watched channel not found yet"],
            ["another code", -32603, UNWATCHED],
        ])("still reports %s for an open channel as poll_failed", async (_, code, message) => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node.error(code, message);
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the watchtower signing poll of ${id} failed: ${message}`, expect.any(RpcError)),
            ]);
        });

        it("submits and emits nothing for a channel with no spend", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.channel.storage.ops.length = 0;
            h.node.result(statusResult(id, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.events).toEqual([]);
        });

        it("does not even read the status of a listed channel this device never registered", async () => {
            const h = await harness();
            await polling(h, [[UNREGISTERED_ID, false]]);
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
            expect(await h.channels.read()).toEqual([UNREGISTERED_ID]);
            expect(h.events).toEqual([]);
        });

        it("calls the node for nothing while the device lists no channel", async () => {
            const h = await harness();
            await polling(h, []);
            await h.step(live());
            expect(h.node.calls()).toEqual([]);
            expect(h.events).toEqual([]);
        });
    });

    describe("a channel that fails", () => {
        it.each<[string, (node: ScriptedNode) => void, string, unknown]>([
            ["refuses", (node) => node.error(-32000, "channel not found"), "channel not found", expect.any(RpcError)],
            [
                "cannot be reached",
                (node) => node.reject(new TypeError("fetch failed")),
                "get_watchtower_signing_status: the request failed",
                expect.any(RpcTransportError),
            ],
        ])("reports a status read the node %s as poll_failed, then answers the next channel", async (_, fail, message, cause) => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [
                [OTHER_ID, true],
                [id, true],
            ]);
            fail(h.node);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(OTHER_ID), watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the watchtower signing poll of ${OTHER_ID} failed: ${message}`, cause),
                signedEvent(id, SETTLEMENT),
            ]);
        });

        it.each<[string, (node: ScriptedNode) => void, string, unknown]>([
            ["refuses", (node) => node.error(-32000, "signature mismatch"), "signature mismatch", expect.any(RpcError)],
            [
                "answers with what no submission returns",
                (node) => node.result({ type: "Rejected" }),
                "submit_watchtower_signature: response.result.type must be one of Applied, AlreadyApplied",
                expect.any(RpcResponseError),
            ],
        ])("reports a submission the node %s as poll_failed, then answers the next channel", async (_, fail, message, cause) => {
            const h = await harness();
            const id = channelIdOf(h);
            await polling(h, [
                [id, true],
                [OTHER_ID, true],
            ]);
            h.node.result(spendResult(id, SETTLEMENT));
            fail(h.node);
            h.node.result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT), watchtowerStatusCall(OTHER_ID)]);
            expect(summarized(h.events)).toStrictEqual([pollFailedEvent(`the watchtower signing poll of ${id} failed: ${message}`, cause)]);
        });

        it.each<[string, unknown]>([
            ["Applied", APPLIED],
            ["AlreadyApplied", ALREADY_APPLIED],
        ])(
            "submits the same signature again on the tick after a submission that failed, and marks it on %s, writing nothing else",
            async (_, answer) => {
                const h = await harness();
                const id = channelIdOf(h);
                h.node.result(spendResult(id, SETTLEMENT)).error(-32000, "node is busy");
                await h.step(live());
                expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, false]]);
                h.channel.storage.ops.length = 0;
                h.node.result(spendResult(id, SETTLEMENT)).result(answer);
                await h.step(live());
                expect(h.node.calls().slice(2)).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
                expect(writes(h.channel.storage)).toEqual(markWrite(h));
                expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, true]]);
                expect(h.events.at(-1)).toStrictEqual(signedEvent(id, SETTLEMENT));
            },
        );

        it("reports a mark that fails as poll_failed, the signature already out, then answers the next channel", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied").mockRejectedValueOnce(new TypeError("storage is full"));
            await polling(h, [
                [id, true],
                [OTHER_ID, true],
            ]);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED).result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT), watchtowerStatusCall(OTHER_ID)]);
            expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, false]]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the watchtower signing poll of ${id} failed: storage is full`, expect.any(TypeError)),
            ]);
        });

        it("reports a fault of the device as poll_failed naming the channel, then answers the next channel", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.channel.storage.map.set(`${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex}`, "garbage");
            await polling(h, [
                [id, true],
                [OTHER_ID, true],
            ]);
            h.node.result(spendResult(id, SETTLEMENT)).result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), watchtowerStatusCall(OTHER_ID)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(
                    `the watchtower signing poll of ${id} failed: stored value at ${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex} is not valid JSON`,
                    expect.any(TypeError),
                ),
            ]);
        });

        it("reports a registration it cannot read as poll_failed, then answers the next channel", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.channel.storage.map.set(`${CHANNEL_ALIAS_KEY_PREFIX}${OTHER_ID}`, "seven");
            await polling(h, [
                [OTHER_ID, true],
                [id, true],
            ]);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(
                    `the watchtower signing poll of ${OTHER_ID} failed: stored value at ${CHANNEL_ALIAS_KEY_PREFIX}${OTHER_ID} is not a channel index`,
                    expect.any(TypeError),
                ),
                signedEvent(id, SETTLEMENT),
            ]);
        });
    });

    describe("an abandoned run", () => {
        it("hands nothing to the dispatch once abandoned during the status read, and signs on the next tick", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const handle = jest.spyOn(h.channel.dispatch, "handleWatchtower");
            const run = live();
            h.channel.storage.ops.length = 0;
            h.node.onCall("get_watchtower_signing_status", () => (run.abandoned = true)).result(spendResult(id, SETTLEMENT));
            await h.step(run);
            expect(handle).not.toHaveBeenCalled();
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(h.events).toEqual([]);

            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(1)).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT)]);
        });

        it("submits nothing once abandoned during the signature, and the next tick submits the same bytes", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            abandonAfterHandleWatchtower(h.channel.dispatch, run);
            h.node.result(spendResult(id, INBOUND_TLC));
            await h.step(run);
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(h.events).toEqual([]);

            h.channel.storage.ops.length = 0;
            h.node.result(spendResult(id, INBOUND_TLC)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(1)).toEqual([watchtowerStatusCall(id), submissionCall(id, INBOUND_TLC)]);
            // The record answers with the signature it holds: the one write is the mark.
            expect(writes(h.channel.storage)).toEqual(markWrite(h));
            expect(h.events).toStrictEqual([signedEvent(id, INBOUND_TLC)]);
        });

        // Fiber never serves an applied request again, so the abandoned run marks it; a node that serves it anyway is answered
        // with the same bytes, which it takes as AlreadyApplied.
        it("marks the spend applied but emits nothing once abandoned during the submission, and answers it again if served again", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            h.node
                .onCall("submit_watchtower_signature", () => (run.abandoned = true))
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(run);
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, true]]);
            expect(h.events).toEqual([]);

            h.node.result(spendResult(id, SETTLEMENT)).result(ALREADY_APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(2)).toEqual([watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT)]);
        });

        it("emits no refusal once abandoned during the signature", async () => {
            const h = await harness({});
            const id = channelIdOf(h);
            const run = live();
            abandonAfterHandleWatchtower(h.channel.dispatch, run);
            h.node.result(spendResult(id, SETTLEMENT));
            await h.step(run);
            expect(h.node.calls()).toEqual([watchtowerStatusCall(id)]);
            expect(h.events).toEqual([]);
        });

        it("emits no failed mark once abandoned during the submission", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node
                .onCall("submit_watchtower_signature", () => (run.abandoned = true))
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no fault once abandoned during the signature", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            h.channel.storage.map.set(`${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex}`, "garbage");
            abandonAfterHandleWatchtower(h.channel.dispatch, run);
            h.node.result(spendResult(id, SETTLEMENT));
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no refusal of another channel's status once abandoned during its read", async () => {
            const h = await harness();
            const run = live();
            h.node.onCall("get_watchtower_signing_status", () => (run.abandoned = true)).result(spendResult(OTHER_ID, SETTLEMENT));
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no error once abandoned during a read that fails", async () => {
            const h = await harness();
            const run = live();
            h.node.onCall("get_watchtower_signing_status", () => (run.abandoned = true)).error(-32000, "channel not found");
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("polls no further channel once abandoned", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            await polling(h, [
                [OTHER_ID, true],
                [id, true],
            ]);
            h.node.onCall("get_watchtower_signing_status", () => (run.abandoned = true)).result(statusResult(OTHER_ID, IDLE));
            await h.step(run);
            expect(h.node.calls()).toEqual([watchtowerStatusCall(OTHER_ID)]);
        });
    });

    it("keeps answering when the emitter throws", async () => {
        const h = await harness({ watchtower: APPROVAL }, () => {
            throw new Error("the host's listener failed");
        });
        const id = channelIdOf(h);
        await polling(h, [
            [OTHER_ID, true],
            [id, true],
        ]);
        h.node.error(-32000, "channel not found").result(spendResult(id, SETTLEMENT)).result(APPLIED);
        await expect(h.step(live())).resolves.toBeUndefined();
        expect(h.node.calls()).toEqual([watchtowerStatusCall(OTHER_ID), watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
        expect(h.events.map((event) => event.type)).toEqual(["ERROR", "WATCHTOWER_SIGNING"]);
        expect(h.events[0]).toMatchObject({ error: expect.any(SdkError) });
    });
});
