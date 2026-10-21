import type { PolicyEngineOptions } from "../../../src/policy";
import { CHANNEL_ALIAS_KEY_PREFIX, CHANNEL_RECORD_KEY_PREFIX } from "../../../src/policy";
import type { ChannelSigningTransition } from "../../../src/protocol";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkEvent } from "../../../src/sdk";
import { SdkError, buildChannelSigningStep } from "../../../src/sdk";
import { ScriptedNode } from "../../mocks/rpc";
import { asRecord } from "../../utils/json-shape";
import { resignPeerHalf } from "../../utils/peer-musig";
import { LIST_CHANNELS_CALL, signingStatusCall } from "../../utils/rpc-answers";
import type { SigningChannel } from "../../utils/signing-channel";
import {
    openSigningChannel,
    secondSessionStatus,
    signatureSubmissionCall,
    signedEventOf,
    signingDeviceKeys,
    signingPeerKeys,
    signingRequestIdOf,
    stageSecondSession,
} from "../../utils/signing-channel";
import type { SigningCaseVector } from "../../utils/signing-vectors";
import { loadSigningVectors, signingCaseOf, signingStatusField } from "../../utils/signing-vectors";
import { withField } from "../../utils/with-field";

const vectors = loadSigningVectors();
const CHANNEL_ID = vectors.channel.channel_id;
// Registered on an index with no record: polled, and idle wherever it is listed.
const OTHER_ID = `0x${"2e".repeat(32)}`;
const OTHER_INDEX = 7;
const UNREGISTERED_ID = `0x${"5a".repeat(32)}`;
const URL = "http://127.0.0.1:8227";
const IDLE = { type: "NoSignatureRequired" };
const APPLIED = { type: "Applied" };
const ALREADY_APPLIED = { type: "AlreadyApplied" };

const SIGNED: readonly ChannelSigningTransition[] = [
    "SendCommitmentSigned",
    "CompleteReceivedCommitment",
    "SendRevokeAndAck",
    "CompleteReceivedRevokeAndAck",
    "SendClosingSigned",
];

type Harness = {
    channel: SigningChannel;
    node: ScriptedNode;
    events: SdkEvent[];
    step: (run: { abandoned: boolean }) => Promise<void>;
};

async function harness(
    transition: ChannelSigningTransition,
    options: PolicyEngineOptions = {},
    onEmit: (event: SdkEvent) => void = () => undefined,
): Promise<Harness> {
    const channel = await openSigningChannel(vectors, caseOf(transition), options);
    await channel.store.claimChannelAlias(OTHER_ID, OTHER_INDEX);
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const step = buildChannelSigningStep({
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        store: channel.store,
        dispatch: channel.dispatch,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
    });
    return { channel, node, events, step };
}

function caseOf(transition: ChannelSigningTransition): SigningCaseVector {
    return signingCaseOf(vectors, transition);
}

function statusResult(status: unknown, channelId = CHANNEL_ID): unknown {
    return { channel_id: channelId, status: structuredClone(status) };
}

function errorEvent(message: string, cause: unknown): unknown {
    return { type: "ERROR", code: "poll_failed", message, cause };
}

function summarized(events: SdkEvent[]): unknown[] {
    return events.map((event) =>
        event.type === "ERROR" ? { type: "ERROR", code: event.error.code, message: event.error.message, cause: event.error.cause } : event,
    );
}

function writesOf(channel: SigningChannel): string[] {
    return channel.storage.ops.filter((op) => op.startsWith("set "));
}

function live(): { abandoned: boolean } {
    return { abandoned: false };
}

describe("buildChannelSigningStep", () => {
    describe("a request the device signs", () => {
        it.each(SIGNED)("submits %s with the vectors' signature and next material, then emits it signed", async (transition) => {
            const kase = caseOf(transition);
            const h = await harness(transition);
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID), signatureSubmissionCall(vectors, kase)]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase)]);
        });

        it("carries next material on every transition the vectors give one, and none on the close", () => {
            const carrying = SIGNED.filter((transition) => caseOf(transition).expected.next_material !== null);
            expect(carrying).toEqual([
                "SendCommitmentSigned",
                "CompleteReceivedCommitment",
                "SendRevokeAndAck",
                "CompleteReceivedRevokeAndAck",
            ]);
        });

        it("resends an already signed request with the same bytes, and takes AlreadyApplied as success", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            h.channel.storage.ops.length = 0;
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(ALREADY_APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(writesOf(h.channel)).toEqual([]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase), signedEventOf(vectors, kase)]);
        });

        it("answers every registered channel the node lists, in its order, and no other", async () => {
            const kase = caseOf("SendRevokeAndAck");
            const h = await harness("SendRevokeAndAck");
            h.node
                .result({ channels: [{ channel_id: UNREGISTERED_ID }, { channel_id: OTHER_ID }, { channel_id: CHANNEL_ID }] })
                .result(statusResult(IDLE, OTHER_ID))
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(OTHER_ID),
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase)]);
        });

        it("answers a registered channel listed beside channels in a state or with a flag this SDK does not know", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            const unknownFlag = {
                channels: [
                    { channel_id: UNREGISTERED_ID, state: { state_name: "Splicing" } },
                    { channel_id: OTHER_ID, state: { state_name: "ShuttingDown", state_flags: "OUR_SPLICE_SENT" } },
                    { channel_id: CHANNEL_ID, state: { state_name: "ChannelReady" } },
                ],
            };
            h.node.result(unknownFlag).result(statusResult(IDLE, OTHER_ID)).result(statusResult(kase.result.status)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(OTHER_ID),
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase)]);
        });
    });

    describe("a request the device refuses", () => {
        it("emits the refusal with its request id and transition, and submits nothing", async () => {
            const kase = caseOf("SignChannelAnnouncement");
            const h = await harness("SignChannelAnnouncement");
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(kase.result.status));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(h.events).toStrictEqual([
                {
                    type: "SIGNING",
                    channelId: CHANNEL_ID,
                    requestId: signingRequestIdOf(kase),
                    transition: "SignChannelAnnouncement",
                    outcome: "refused",
                    error: {
                        code: "policy_refusal",
                        message: "a channel announcement is never signed: every channel of this device is private",
                    },
                },
            ]);
        });

        it("emits a status it cannot read as refused, with neither request id nor transition", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            h.channel.storage.ops.length = 0;
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(withField(kase.result.status, "transition", "SignEverything")));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(writesOf(h.channel)).toEqual([]);
            expect(h.events).toStrictEqual([
                {
                    type: "SIGNING",
                    channelId: CHANNEL_ID,
                    requestId: null,
                    transition: null,
                    outcome: "refused",
                    error: {
                        code: "malformed",
                        message:
                            "response.result.status.transition must be one of SendCommitmentSigned, CompleteReceivedCommitment, SendRevokeAndAck, CompleteReceivedRevokeAndAck, SendClosingSigned, SignChannelAnnouncement",
                    },
                },
            ]);
        });

        it("refuses the status of another channel as malformed, without handing it to the dispatch", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            const handle = jest.spyOn(h.channel.dispatch, "handle");
            h.channel.storage.ops.length = 0;
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(kase.result.status, OTHER_ID));
            await h.step(live());
            expect(handle).not.toHaveBeenCalled();
            expect(writesOf(h.channel)).toEqual([]);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(h.events).toStrictEqual([
                {
                    type: "SIGNING",
                    channelId: CHANNEL_ID,
                    requestId: null,
                    transition: null,
                    outcome: "refused",
                    error: { code: "malformed", message: `the node answered the signing status of ${CHANNEL_ID} with that of ${OTHER_ID}` },
                },
            ]);
        });

        it("emits the refusal again on every tick the request stays pending", async () => {
            const kase = caseOf("SignChannelAnnouncement");
            const h = await harness("SignChannelAnnouncement");
            for (let tick = 0; tick < 2; tick++) {
                h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(kase.result.status));
                await h.step(live());
            }
            expect(h.events.map((event) => (event.type === "SIGNING" ? event.outcome : event.type))).toEqual(["refused", "refused"]);
        });
    });

    describe("a second session on a served slot", () => {
        const keys = signingDeviceKeys(vectors);
        const peerFundingKey = signingPeerKeys(vectors).fundingKey;

        async function servedChannel(nonceReuse: "refuse" | "allow"): Promise<Harness> {
            const h = await harness("SendCommitmentSigned", { nonceReuse });
            await stageSecondSession(vectors, h.channel);
            const first = caseOf("SendCommitmentSigned");
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(first.result.status))
                .result(APPLIED);
            await h.step(live());
            return h;
        }

        it("emits the second session signed under allow as a warning, after submitting it", async () => {
            const h = await servedChannel("allow");
            const second = secondSessionStatus(vectors);
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(second.value))
                .result(APPLIED);
            await h.step(live());
            const sent = h.node.calls().at(-1);
            expect(sent?.method).toBe("submit_channel_signature");
            expect(asRecord(sent?.params, "params").request_id).toBe(signingRequestIdOf(caseOf("CompleteReceivedCommitment")));
            expect(h.events).toStrictEqual([
                signedEventOf(vectors, caseOf("SendCommitmentSigned")),
                signedEventOf(vectors, caseOf("CompleteReceivedCommitment"), "warning"),
            ]);
        });

        it("refuses a third session under allow, submitting nothing", async () => {
            const h = await servedChannel("allow");
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(secondSessionStatus(vectors).value))
                .result(APPLIED);
            await h.step(live());
            const first = caseOf("SendCommitmentSigned");
            const third = resignPeerHalf(signingStatusField(first), keys, peerFundingKey, 0x72);
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(third.value));
            await h.step(live());
            expect(h.node.calls().slice(-2)).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(h.events.at(-1)).toStrictEqual({
                type: "SIGNING",
                channelId: CHANNEL_ID,
                requestId: signingRequestIdOf(first),
                transition: "SendCommitmentSigned",
                outcome: "refused",
                error: {
                    code: "policy_refusal",
                    message: "slot COMMITMENT:4 has already served two signing sessions, the most one nonce can",
                },
            });
        });

        it("refuses the second session by default", async () => {
            const h = await servedChannel("refuse");
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(secondSessionStatus(vectors).value));
            await h.step(live());
            expect(h.node.calls().slice(-2)).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(h.events.at(-1)).toStrictEqual({
                type: "SIGNING",
                channelId: CHANNEL_ID,
                requestId: signingRequestIdOf(caseOf("CompleteReceivedCommitment")),
                transition: "CompleteReceivedCommitment",
                outcome: "refused",
                error: { code: "policy_refusal", message: "slot COMMITMENT:4 has already served a different signing session" },
            });
        });
    });

    describe("nothing to answer", () => {
        it("submits and emits nothing for a channel with no request", async () => {
            const h = await harness("SendCommitmentSigned");
            h.channel.storage.ops.length = 0;
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(IDLE));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(writesOf(h.channel)).toEqual([]);
            expect(h.events).toEqual([]);
        });

        it("does not even read the status of a channel this device never registered", async () => {
            const h = await harness("SendCommitmentSigned");
            h.node.result({ channels: [{ channel_id: UNREGISTERED_ID }] });
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL]);
            expect(h.events).toEqual([]);
        });

        it("reads nothing more when the node lists no channel", async () => {
            const h = await harness("SendCommitmentSigned");
            h.node.result({ channels: [] });
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL]);
            expect(h.events).toEqual([]);
        });
    });

    describe("a channel that fails", () => {
        it.each<[string, (node: ScriptedNode) => void, string, unknown]>([
            ["refuses", (node) => node.error(-32000, "channel not found"), "channel not found", expect.any(RpcError)],
            [
                "cannot be reached",
                (node) => node.reject(new TypeError("fetch failed")),
                "get_channel_signing_status: the request failed",
                expect.any(RpcTransportError),
            ],
        ])("reports a status read the node %s as poll_failed, then answers the next channel", async (_, fail, message, cause) => {
            const kase = caseOf("CompleteReceivedCommitment");
            const h = await harness("CompleteReceivedCommitment");
            h.node.result({ channels: [{ channel_id: OTHER_ID }, { channel_id: CHANNEL_ID }] });
            fail(h.node);
            h.node.result(statusResult(kase.result.status)).result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(OTHER_ID),
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(summarized(h.events)).toStrictEqual([
                errorEvent(`the signing poll of ${OTHER_ID} failed: ${message}`, cause),
                signedEventOf(vectors, kase),
            ]);
        });

        it.each<[string, (node: ScriptedNode) => void, string, unknown]>([
            ["refuses", (node) => node.error(-32000, "result mismatch"), "result mismatch", expect.any(RpcError)],
            [
                "answers with what no submission returns",
                (node) => node.result({ type: "Rejected" }),
                "submit_channel_signature: response.result.type must be one of Applied, AlreadyApplied",
                expect.any(RpcResponseError),
            ],
        ])("reports a submission the node %s as poll_failed, then answers the next channel", async (_, fail, message, cause) => {
            const kase = caseOf("SendClosingSigned");
            const h = await harness("SendClosingSigned");
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }, { channel_id: OTHER_ID }] }).result(statusResult(kase.result.status));
            fail(h.node);
            h.node.result(statusResult(IDLE, OTHER_ID));
            await h.step(live());
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
                signingStatusCall(OTHER_ID),
            ]);
            expect(summarized(h.events)).toStrictEqual([errorEvent(`the signing poll of ${CHANNEL_ID} failed: ${message}`, cause)]);
        });

        it("submits the signature again on the tick after a submission that failed", async () => {
            const kase = caseOf("SendClosingSigned");
            const h = await harness("SendClosingSigned");
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .error(-32000, "node is busy");
            await h.step(live());
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(3)).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(h.events.at(-1)).toStrictEqual(signedEventOf(vectors, kase));
        });

        it("reports a fault of the device as poll_failed naming the channel, then answers the next channel", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            h.channel.storage.map.set(`${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex}`, "garbage");
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }, { channel_id: OTHER_ID }] })
                .result(statusResult(kase.result.status))
                .result(statusResult(IDLE, OTHER_ID));
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID), signingStatusCall(OTHER_ID)]);
            expect(summarized(h.events)).toStrictEqual([
                errorEvent(
                    `the signing poll of ${CHANNEL_ID} failed: stored value at ${CHANNEL_RECORD_KEY_PREFIX}${h.channel.channelIndex} is not valid JSON`,
                    expect.any(TypeError),
                ),
            ]);
        });

        it("reports a registration it cannot read as poll_failed, then answers the next channel", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            h.channel.storage.map.set(`${CHANNEL_ALIAS_KEY_PREFIX}${OTHER_ID}`, "seven");
            h.node
                .result({ channels: [{ channel_id: OTHER_ID }, { channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID), signatureSubmissionCall(vectors, kase)]);
            expect(summarized(h.events)).toStrictEqual([
                errorEvent(
                    `the signing poll of ${OTHER_ID} failed: stored value at ${CHANNEL_ALIAS_KEY_PREFIX}${OTHER_ID} is not a channel index`,
                    expect.any(TypeError),
                ),
                signedEventOf(vectors, kase),
            ]);
        });

        it("rejects when the node's channels cannot be listed, reading nothing more", async () => {
            const h = await harness("SendCommitmentSigned");
            h.node.error(-32000, "node is syncing");
            await expect(h.step(live())).rejects.toEqual(new RpcError("list_channels", -32000, "node is syncing"));
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL]);
            expect(h.events).toEqual([]);
        });
    });

    describe("an abandoned run", () => {
        it("hands nothing to the dispatch once abandoned during the status read, and signs on the next tick", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            const handle = jest.spyOn(h.channel.dispatch, "handle");
            const run = live();
            h.channel.storage.ops.length = 0;
            h.node
                .onCall("get_channel_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status));
            await h.step(run);
            expect(handle).not.toHaveBeenCalled();
            expect(writesOf(h.channel)).toEqual([]);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(h.events).toEqual([]);

            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(2)).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase)]);
        });

        it("submits nothing once abandoned during the signature, and the next tick submits the same bytes", async () => {
            const kase = caseOf("CompleteReceivedRevokeAndAck");
            const h = await harness("CompleteReceivedRevokeAndAck");
            const run = live();
            abandonAfterHandle(h, run);
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(kase.result.status));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
            expect(h.events).toEqual([]);

            h.channel.storage.ops.length = 0;
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(2)).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            // The sign-once store answers with the bytes it signed, writing nothing.
            expect(writesOf(h.channel)).toEqual([]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase)]);
        });

        it("emits nothing once abandoned during the submission, and the next tick resends it and emits", async () => {
            const kase = caseOf("SendRevokeAndAck");
            const h = await harness("SendRevokeAndAck");
            const run = live();
            h.node
                .onCall("submit_channel_signature", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(APPLIED);
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID), signatureSubmissionCall(vectors, kase)]);
            expect(h.events).toEqual([]);

            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status))
                .result(ALREADY_APPLIED);
            await h.step(live());
            expect(h.node.calls().slice(3)).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(CHANNEL_ID),
                signatureSubmissionCall(vectors, kase),
            ]);
            expect(h.events).toStrictEqual([signedEventOf(vectors, kase)]);
        });

        it("emits no refusal once abandoned during the signature", async () => {
            const kase = caseOf("SignChannelAnnouncement");
            const h = await harness("SignChannelAnnouncement");
            const run = live();
            abandonAfterHandle(h, run);
            h.node.result({ channels: [{ channel_id: CHANNEL_ID }] }).result(statusResult(kase.result.status));
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no refusal of another channel's status once abandoned during its read", async () => {
            const kase = caseOf("SendCommitmentSigned");
            const h = await harness("SendCommitmentSigned");
            const run = live();
            h.node
                .onCall("get_channel_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result(statusResult(kase.result.status, OTHER_ID));
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("emits no error once abandoned during a read that fails", async () => {
            const h = await harness("SendCommitmentSigned");
            const run = live();
            h.node
                .onCall("get_channel_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .error(-32000, "channel not found");
            await h.step(run);
            expect(h.events).toEqual([]);
        });

        it("polls no further channel once abandoned", async () => {
            const h = await harness("SendCommitmentSigned");
            const run = live();
            h.node
                .onCall("get_channel_signing_status", () => (run.abandoned = true))
                .result({ channels: [{ channel_id: OTHER_ID }, { channel_id: CHANNEL_ID }] })
                .result(statusResult(IDLE, OTHER_ID));
            await h.step(run);
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, signingStatusCall(OTHER_ID)]);
        });
    });

    it("keeps answering when the emitter throws", async () => {
        const kase = caseOf("SendCommitmentSigned");
        const h = await harness("SendCommitmentSigned", {}, () => {
            throw new Error("the host's listener failed");
        });
        h.node
            .result({ channels: [{ channel_id: OTHER_ID }, { channel_id: CHANNEL_ID }] })
            .error(-32000, "channel not found")
            .result(statusResult(kase.result.status))
            .result(APPLIED);
        await expect(h.step(live())).resolves.toBeUndefined();
        expect(h.node.calls()).toEqual([
            LIST_CHANNELS_CALL,
            signingStatusCall(OTHER_ID),
            signingStatusCall(CHANNEL_ID),
            signatureSubmissionCall(vectors, kase),
        ]);
        expect(h.events.map((event) => event.type)).toEqual(["ERROR", "SIGNING"]);
        expect(h.events[0]).toMatchObject({ error: expect.any(SdkError) });
    });
});

function abandonAfterHandle(h: Harness, run: { abandoned: boolean }): void {
    const handle = h.channel.dispatch.handle.bind(h.channel.dispatch);
    jest.spyOn(h.channel.dispatch, "handle").mockImplementationOnce(async (channelId, status) => {
        const outcome = await handle(channelId, status);
        run.abandoned = true;
        return outcome;
    });
}
