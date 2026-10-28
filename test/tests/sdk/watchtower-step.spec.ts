import type { PolicyEngineOptions } from "../../../src/policy";
import { CHANNEL_ALIAS_KEY_PREFIX, CHANNEL_RECORD_KEY_PREFIX } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkEvent } from "../../../src/sdk";
import { SdkError, buildWatchtowerSigningStep } from "../../../src/sdk";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall } from "../../utils/rpc-answers";
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
import { rejection } from "../../utils/rejection";
import { abandonAfterHandleWatchtower, live, pollFailedEvent, summarized } from "../../utils/step-run";
import { withField } from "../../utils/with-field";
import { writes } from "../../utils/stored-records";

const vectors = loadSigningVectors();
// Registered on an index with no record: polled, and idle wherever it is listed.
const OTHER_ID = `0x${"2e".repeat(32)}`;
const OTHER_INDEX = 7;
const UNREGISTERED_ID = `0x${"5a".repeat(32)}`;
const URL = "http://127.0.0.1:8227";
const IDLE = { type: "NoSignatureRequired" };
const READY = { state_name: "ChannelReady" };
// Before `TxComplete`, when fiber has created no watch row yet.
const COLLABORATING = { state_name: "CollaboratingFundingTx", state_flags: "AWAITING_REMOTE_TX_COLLABORATION_MSG" };
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
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const step = buildWatchtowerSigningStep({
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        store: channel.store,
        policy: channel.policy,
        dispatch: channel.dispatch,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
    });
    return { channel, node, events, step };
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
                h.node
                    .result({ channels: [{ channel_id: id, state: READY }] })
                    .result(spendResult(id, spend))
                    .result(APPLIED);
                await h.step(live());
                expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id), submissionCall(id, spend)]);
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
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            expect(order).toEqual(["submit", "mark", "WATCHTOWER_SIGNING"]);
        });

        // Fiber keeps the requests a rebuild superseded, and serves the lowest id first: one may come after the spend it signed.
        it("submits a request for the unlock of a spend it signed already, marking nothing, and emits it signed", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            const supersededId = `0x${"0d".repeat(32)}`;
            const mark = jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied");
            h.channel.storage.ops.length = 0;
            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(statusResult(id, withField(watchtowerStatusField(SETTLEMENT).value, "request_id", supersededId)))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(3)).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
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
            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            h.channel.storage.ops.length = 0;
            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(ALREADY_APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
            ]);
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT), signedEvent(id, SETTLEMENT)]);
        });

        it("answers every registered channel the node lists, in its order, and no other", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node
                .result({
                    channels: [
                        { channel_id: UNREGISTERED_ID, state: READY },
                        { channel_id: OTHER_ID, state: READY },
                        { channel_id: id, state: READY },
                    ],
                })
                .result(statusResult(OTHER_ID, IDLE))
                .result(spendResult(id, INBOUND_TLC))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(OTHER_ID),
                watchtowerStatusCall(id),
                submissionCall(id, INBOUND_TLC),
            ]);
            expect(h.events).toStrictEqual([signedEvent(id, INBOUND_TLC)]);
        });
    });

    describe("a spend the device refuses", () => {
        it("emits the refusal of a device whose host approved no destination, with its request id and purpose, submitting nothing", async () => {
            const h = await harness({});
            const id = channelIdOf(h);
            h.channel.storage.ops.length = 0;
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(spendResult(id, OUTBOUND_TLC));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
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
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(statusResult(id, watchtowerStatusField(variant).value));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
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
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(statusResult(id, status));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
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
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(spendResult(OTHER_ID, SETTLEMENT));
            await h.step(live());
            expect(handle).not.toHaveBeenCalled();
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
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
                h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(spendResult(id, SETTLEMENT));
                await h.step(live());
            }
            expect(h.events.map((event) => (event.type === "WATCHTOWER_SIGNING" ? event.outcome : event.type))).toEqual([
                "refused",
                "refused",
            ]);
        });
    });

    describe("the channels it polls", () => {
        it.each(["COOPERATIVE", "ABANDONED", "FUNDING_ABORTED"])(
            "skips a channel closed %s, which fiber's watchtower no longer watches or never did",
            async (flag) => {
                const h = await harness();
                const id = channelIdOf(h);
                h.node
                    .result({
                        channels: [
                            { channel_id: id, state: { state_name: "Closed", state_flags: flag } },
                            { channel_id: OTHER_ID, state: READY },
                        ],
                    })
                    .result(statusResult(OTHER_ID, IDLE));
                await h.step(live());
                expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(OTHER_ID)]);
                expect(h.events).toEqual([]);
            },
        );

        it.each<[string, unknown]>([
            ["closed by the device's own commitment", { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL" }],
            ["closed by the peer's commitment", { state_name: "Closed", state_flags: "UNCOOPERATIVE_REMOTE" }],
            [
                "closed and waiting for the settlement on chain",
                { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT" },
            ],
            ["closed with only the settlement pending", { state_name: "Closed", state_flags: "WAITING_ONCHAIN_SETTLEMENT" }],
            ["shutting down with its commitment broadcast", { state_name: "ShuttingDown", state_flags: "WAITING_COMMITMENT_CONFIRMATION" }],
            ["closed with no flag", { state_name: "Closed", state_flags: "" }],
            ["closed with a flag this SDK does not know", { state_name: "Closed", state_flags: "SPLICE_ABORTED" }],
            [
                "closed with a known close flag beside an unknown one",
                { state_name: "Closed", state_flags: "UNCOOPERATIVE_REMOTE|SPLICE_ABORTED" },
            ],
            ["in a state this SDK does not know", { state_name: "Splicing" }],
            ["in another state under a skipped flag's name", { state_name: "ShuttingDown", state_flags: "COOPERATIVE" }],
            ["stale", { state_name: "Stale" }],
        ])("polls a channel %s, and signs its spend", async (_, state) => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node
                .result({ channels: [{ channel_id: id, state }] })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT)]);
        });

        it("rejects a listing with a channel whose state it cannot read, reading nothing more", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node.result({ channels: [{ channel_id: OTHER_ID, state: READY }, { channel_id: id }] });
            const error = await rejection(h.step(live()));
            expect(error).toBeInstanceOf(RpcResponseError);
            expect((error as RpcResponseError).message).toBe("list_channels: response.result.channels[1].state must be an object");
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toEqual([]);
        });
    });

    describe("nothing to answer", () => {
        it.each<[string, unknown]>([
            ["still opening", COLLABORATING],
            ["ready", READY],
        ])("reads fiber's answer for a channel %s with no watch row yet as nothing pending, then answers the next", async (_, state) => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node
                .result({
                    channels: [
                        { channel_id: id, state },
                        { channel_id: OTHER_ID, state: READY },
                    ],
                })
                .error(-32000, UNWATCHED)
                .result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id), watchtowerStatusCall(OTHER_ID)]);
            expect(h.events).toEqual([]);
        });

        it.each<[string, unknown, number, string]>([
            ["another message", READY, -32000, "watched channel not found yet"],
            ["another code", READY, -32603, UNWATCHED],
            [
                "fiber's answer for a channel closed by its commitment",
                { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL" },
                -32000,
                UNWATCHED,
            ],
        ])("still reports %s as poll_failed", async (_, state, code, message) => {
            const h = await harness();
            const id = channelIdOf(h);
            h.node.result({ channels: [{ channel_id: id, state }] }).error(code, message);
            await h.step(live());
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the watchtower signing poll of ${id} failed: ${message}`, expect.any(RpcError)),
            ]);
        });

        it("submits and emits nothing for a channel with no spend", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.channel.storage.ops.length = 0;
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(statusResult(id, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.events).toEqual([]);
        });

        it("does not even read the status of a channel this device never registered", async () => {
            const h = await harness();
            h.node.result({ channels: [{ channel_id: UNREGISTERED_ID, state: READY }] });
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toEqual([]);
        });

        it("reads nothing more when the node lists no channel", async () => {
            const h = await harness();
            h.node.result({ channels: [] });
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
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
            h.node.result({
                channels: [
                    { channel_id: OTHER_ID, state: READY },
                    { channel_id: id, state: READY },
                ],
            });
            fail(h.node);
            h.node.result(spendResult(id, SETTLEMENT)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(OTHER_ID),
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
            ]);
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
            h.node
                .result({
                    channels: [
                        { channel_id: id, state: READY },
                        { channel_id: OTHER_ID, state: READY },
                    ],
                })
                .result(spendResult(id, SETTLEMENT));
            fail(h.node);
            h.node.result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
                watchtowerStatusCall(OTHER_ID),
            ]);
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
                h.node
                    .result({ channels: [{ channel_id: id, state: READY }] })
                    .result(spendResult(id, SETTLEMENT))
                    .error(-32000, "node is busy");
                await h.step(live());
                expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, false]]);
                h.channel.storage.ops.length = 0;
                h.node
                    .result({ channels: [{ channel_id: id, state: READY }] })
                    .result(spendResult(id, SETTLEMENT))
                    .result(answer);
                await h.step(live());
                expect(h.node.calls().slice(3)).toEqual([
                    LIST_CHANNELS_WITH_CLOSED_CALL,
                    watchtowerStatusCall(id),
                    submissionCall(id, SETTLEMENT),
                ]);
                expect(writes(h.channel.storage)).toEqual(markWrite(h));
                expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, true]]);
                expect(h.events.at(-1)).toStrictEqual(signedEvent(id, SETTLEMENT));
            },
        );

        it("reports a mark that fails as poll_failed, the signature already out, then answers the next channel", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node
                .result({
                    channels: [
                        { channel_id: id, state: READY },
                        { channel_id: OTHER_ID, state: READY },
                    ],
                })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED)
                .result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
                watchtowerStatusCall(OTHER_ID),
            ]);
            expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, false]]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(`the watchtower signing poll of ${id} failed: storage is full`, expect.any(TypeError)),
            ]);
        });

        it("reports a fault of the device as poll_failed naming the channel, then answers the next channel", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            h.channel.storage.map.set(`${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex}`, "garbage");
            h.node
                .result({
                    channels: [
                        { channel_id: id, state: READY },
                        { channel_id: OTHER_ID, state: READY },
                    ],
                })
                .result(spendResult(id, SETTLEMENT))
                .result(statusResult(OTHER_ID, IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id), watchtowerStatusCall(OTHER_ID)]);
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
            h.node
                .result({
                    channels: [
                        { channel_id: OTHER_ID, state: READY },
                        { channel_id: id, state: READY },
                    ],
                })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(summarized(h.events)).toStrictEqual([
                pollFailedEvent(
                    `the watchtower signing poll of ${OTHER_ID} failed: stored value at ${CHANNEL_ALIAS_KEY_PREFIX}${OTHER_ID} is not a channel index`,
                    expect.any(TypeError),
                ),
                signedEvent(id, SETTLEMENT),
            ]);
        });

        it("rejects when the node's channels cannot be listed, reading nothing more", async () => {
            const h = await harness();
            h.node.error(-32000, "node is syncing");
            await expect(h.step(live())).rejects.toEqual(new RpcError("list_channels", -32000, "node is syncing"));
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
            expect(h.events).toEqual([]);
        });
    });

    describe("an abandoned run", () => {
        it("hands nothing to the dispatch once abandoned during the status read, and signs on the next tick", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const handle = jest.spyOn(h.channel.dispatch, "handleWatchtower");
            const run = live();
            h.channel.storage.ops.length = 0;
            h.node
                .onCall("get_watchtower_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT));
            await h.step(run);
            expect(handle).not.toHaveBeenCalled();
            expect(writes(h.channel.storage)).toEqual([]);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
            expect(h.events).toEqual([]);

            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(2)).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
            ]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT)]);
        });

        it("submits nothing once abandoned during the signature, and the next tick submits the same bytes", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            abandonAfterHandleWatchtower(h.channel.dispatch, run);
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(spendResult(id, INBOUND_TLC));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
            expect(h.events).toEqual([]);

            h.channel.storage.ops.length = 0;
            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, INBOUND_TLC))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(2)).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, INBOUND_TLC),
            ]);
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
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(APPLIED);
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id), submissionCall(id, SETTLEMENT)]);
            expect(await appliedOf(h)).toEqual([[SETTLEMENT.request_id, true]]);
            expect(h.events).toEqual([]);

            h.node
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(id, SETTLEMENT))
                .result(ALREADY_APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(3)).toEqual([
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(id),
                submissionCall(id, SETTLEMENT),
            ]);
            expect(h.events).toStrictEqual([signedEvent(id, SETTLEMENT)]);
        });

        it("emits no refusal once abandoned during the signature", async () => {
            const h = await harness({});
            const id = channelIdOf(h);
            const run = live();
            abandonAfterHandleWatchtower(h.channel.dispatch, run);
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(spendResult(id, SETTLEMENT));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(id)]);
            expect(h.events).toEqual([]);
        });

        it("emits no failed mark once abandoned during the submission", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            jest.spyOn(h.channel.policy, "markWatchtowerSpendApplied").mockRejectedValueOnce(new TypeError("storage is full"));
            h.node
                .onCall("submit_watchtower_signature", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: id, state: READY }] })
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
            h.node.result({ channels: [{ channel_id: id, state: READY }] }).result(spendResult(id, SETTLEMENT));
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no refusal of another channel's status once abandoned during its read", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            h.node
                .onCall("get_watchtower_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: id, state: READY }] })
                .result(spendResult(OTHER_ID, SETTLEMENT));
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no error once abandoned during a read that fails", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            h.node
                .onCall("get_watchtower_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: id, state: READY }] })
                .error(-32000, "channel not found");
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("polls no further channel once abandoned", async () => {
            const h = await harness();
            const id = channelIdOf(h);
            const run = live();
            h.node
                .onCall("get_watchtower_signing_status", () => (run.abandoned = true))
                .result({
                    channels: [
                        { channel_id: OTHER_ID, state: READY },
                        { channel_id: id, state: READY },
                    ],
                })
                .result(statusResult(OTHER_ID, IDLE));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(OTHER_ID)]);
        });
    });

    it("keeps answering when the emitter throws", async () => {
        const h = await harness({ watchtower: APPROVAL }, () => {
            throw new Error("the host's listener failed");
        });
        const id = channelIdOf(h);
        h.node
            .result({
                channels: [
                    { channel_id: OTHER_ID, state: READY },
                    { channel_id: id, state: READY },
                ],
            })
            .error(-32000, "channel not found")
            .result(spendResult(id, SETTLEMENT))
            .result(APPLIED);
        await expect(h.step(live())).resolves.toBeUndefined();
        expect(h.node.calls()).toEqual([
            LIST_CHANNELS_WITH_CLOSED_CALL,
            watchtowerStatusCall(OTHER_ID),
            watchtowerStatusCall(id),
            submissionCall(id, SETTLEMENT),
        ]);
        expect(h.events.map((event) => event.type)).toEqual(["ERROR", "WATCHTOWER_SIGNING"]);
        expect(h.events[0]).toMatchObject({ error: expect.any(SdkError) });
    });
});
