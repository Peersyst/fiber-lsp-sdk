import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import type { FiberLspSdkOptions, SdkContext, SdkEvent } from "../../../src/sdk";
import { DEFAULT_POLL_INTERVAL_MS, FiberLspSdk, POLL_STEP_TIMEOUT_MS, SdkError } from "../../../src/sdk";
import type { ChannelSigningTransition } from "../../../src/protocol";
import type { SignerRefusal } from "../../../src/signer";
import { FetchMock, ScriptedNode } from "../../mocks/rpc";
import { InMemorySignerStorage } from "../../mocks/policy";
import { flush } from "../../utils/flush";
import { TimerMock } from "../../mocks/common";
import { loadInteropVectors } from "../../utils/interop-vectors";
import { rejection } from "../../utils/rejection";
import { LIST_CHANNELS_CALL, LIST_CHANNELS_WITH_CLOSED_CALL, signingStatusCall, watchtowerStatusCall } from "../../utils/rpc-answers";
import type { SigningChannel } from "../../utils/signing-channel";
import {
    openSigningChannel,
    secondSessionStatus,
    signatureSubmissionCall,
    signedEventOf,
    signingCommitmentLock,
    signingRequestIdOf,
    stageSecondSession,
} from "../../utils/signing-channel";
import {
    loadSigningVectors,
    signingCaseOf,
    signingStatusField,
    watchtowerApprovalOf,
    watchtowerSpendOf,
    watchtowerStatusField,
} from "../../utils/signing-vectors";
import { withRuntime } from "../../utils/with-runtime";

const vectors = loadInteropVectors();
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const PEER_KEYS = deriveChannelKeys(hexToBytes(vectors.digest.remote.seed));
const LSP_PUBKEY = pubkeyOf(PEER_KEYS.fundingKey);
const RPC_URL = "http://fiber.example:8227";
const TOKEN = "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiDs-token_example=";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const POLL_INTERVAL_MS = 7_000;
const NOW_MS = 1_791_367_200_250;
const signing = loadSigningVectors();
const SIGNING_CHANNEL_ID = signing.channel.channel_id;
const DEV_NETWORK = {
    commitmentLock: { codeHash: new Uint8Array(32).fill(0x5d), hashType: "data1" },
    invoiceCurrency: "Fibd",
    fundingLockCellDepsCount: 3,
} as const;
const APPROVAL = watchtowerApprovalOf(signing);
const IDLE = { type: "NoSignatureRequired" };
const READY = { state_name: "ChannelReady" };

function harness(overrides: Partial<FiberLspSdkOptions> = {}, seed: Uint8Array = MASTER_SEED) {
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    const fetch = new FetchMock();
    const events: SdkEvent[] = [];
    const sdk = new FiberLspSdk(seed, {
        network: "testnet",
        storage,
        rpcUrl: RPC_URL,
        biscuitToken: TOKEN,
        lspPubkey: LSP_PUBKEY,
        fetch: fetch.fetch,
        timer,
        now: () => NOW_MS,
        pollIntervalMs: POLL_INTERVAL_MS,
        ...overrides,
    });
    sdk.onEvent((event) => events.push(event));
    const errors = (): SdkError[] => events.flatMap((event) => (event.type === "ERROR" ? [event.error] : []));
    const polls = (): number => timer.delays.filter((delay) => delay === POLL_INTERVAL_MS).length;
    return { sdk, timer, storage, fetch, events, errors, polls };
}

// Read through the private context until the operations observe the wiring.
function contextOf(sdk: FiberLspSdk): SdkContext {
    return (sdk as unknown as { context: SdkContext }).context;
}

type SigningHarness = {
    sdk: FiberLspSdk;
    node: ScriptedNode;
    events: SdkEvent[];
};

async function signingHarness(
    overrides: Partial<FiberLspSdkOptions>,
    prepare: (channel: SigningChannel) => Promise<void> = async () => undefined,
): Promise<SigningHarness> {
    const storage = new InMemorySignerStorage();
    const channel = await openSigningChannel(signing, signingCaseOf(signing, "SendCommitmentSigned"), {}, storage);
    await prepare(channel);
    const node = new ScriptedNode();
    const events: SdkEvent[] = [];
    const sdk = new FiberLspSdk(hexToBytes(signing.device.master_seed), {
        network: "testnet",
        storage,
        rpcUrl: RPC_URL,
        lspPubkey: hexToBytes(signing.peer.funding_pubkey),
        fetch: node.fetch,
        timer: new TimerMock(),
        now: () => NOW_MS,
        pollIntervalMs: POLL_INTERVAL_MS,
        ...overrides,
    });
    sdk.onEvent((event) => events.push(event));
    return { sdk, node, events };
}

async function tickOver(h: SigningHarness, status: unknown, submits: boolean, watchtowerStatus: unknown = IDLE): Promise<void> {
    h.node.result({ channels: [{ channel_id: SIGNING_CHANNEL_ID }] }).result({ channel_id: SIGNING_CHANNEL_ID, status });
    if (submits) h.node.result({ type: "Applied" });
    h.node
        .result({ channels: [{ channel_id: SIGNING_CHANNEL_ID, state: READY }] })
        .result({ channel_id: SIGNING_CHANNEL_ID, status: watchtowerStatus });
    h.sdk.connect();
    await flush();
    h.sdk.disconnect();
}

function refusedEvent(transition: ChannelSigningTransition, error: SignerRefusal): SdkEvent {
    const kase = signingCaseOf(signing, transition);
    return { type: "SIGNING", channelId: SIGNING_CHANNEL_ID, requestId: signingRequestIdOf(kase), transition, outcome: "refused", error };
}

describe("FiberLspSdk", () => {
    describe("construction", () => {
        it("polls nothing and schedules nothing until connect()", () => {
            const h = harness();
            expect(h.timer.pending).toBe(0);
            expect(h.fetch.requests).toEqual([]);
            expect(h.storage.ops).toEqual([]);
            expect(h.events).toEqual([]);
        });

        it.each([
            ["a master seed of 31 bytes", {}, new Uint8Array(31), new TypeError("masterSeed must be 32 bytes, got 31")],
            [
                "a master seed in hex",
                {},
                bytesToHex(MASTER_SEED) as unknown as Uint8Array,
                new TypeError("masterSeed must be a Uint8Array"),
            ],
            ["no storage", { storage: undefined }, MASTER_SEED, new TypeError("storage must be an object")],
            [
                "a storage without get",
                { storage: { set: () => undefined } as never },
                MASTER_SEED,
                new TypeError("storage.get must be a function"),
            ],
            [
                "a storage without set",
                { storage: { get: () => null } as never },
                MASTER_SEED,
                new TypeError("storage.set must be a function"),
            ],
            ["a fetch that is not a function", { fetch: "fetch" as never }, MASTER_SEED, new TypeError("fetch must be a function")],
            ["a clock that is not a function", { now: 1_791_367_200_250 as never }, MASTER_SEED, new TypeError("now must be a function")],
            ["a timer that is not an object", { timer: (() => undefined) as never }, MASTER_SEED, new TypeError("timer must be an object")],
            ["a timer without schedule", { timer: {} as never }, MASTER_SEED, new TypeError("timer.schedule must be a function")],
            ["a null token", { biscuitToken: null as never }, MASTER_SEED, new TypeError("token must be printable ASCII without spaces")],
            ["an empty rpc url", { rpcUrl: "" }, MASTER_SEED, new TypeError("rpcUrl must be a non-empty string")],
            ["an LSP key of 32 bytes", { lspPubkey: new Uint8Array(32) }, MASTER_SEED, new TypeError("lspPubkey must be 33 bytes, got 32")],
            [
                "an LSP key off the curve",
                { lspPubkey: Uint8Array.of(0x02, ...new Uint8Array(32)) },
                MASTER_SEED,
                new TypeError("lspPubkey must be a compressed point on secp256k1"),
            ],
            [
                "an LSP key under the uncompressed prefix",
                { lspPubkey: Uint8Array.of(0x04, ...LSP_PUBKEY.subarray(1)) },
                MASTER_SEED,
                new TypeError("lspPubkey must be a compressed point on secp256k1"),
            ],
            [
                "an LSP key in hex",
                { lspPubkey: bytesToHex(LSP_PUBKEY) as unknown as Uint8Array },
                MASTER_SEED,
                new TypeError("lspPubkey must be a Uint8Array"),
            ],
            [
                "a null poll interval",
                { pollIntervalMs: null as never },
                MASTER_SEED,
                new RangeError("pollIntervalMs must be an integer between 1 and 2147483647, got null"),
            ],
            ["a null fetch", { fetch: null as never }, MASTER_SEED, new TypeError("fetch must be a function")],
            ["a null clock", { now: null as never }, MASTER_SEED, new TypeError("now must be a function")],
            ["a null timer", { timer: null as never }, MASTER_SEED, new TypeError("timer must be an object")],
            [
                "a poll interval of 0",
                { pollIntervalMs: 0 },
                MASTER_SEED,
                new RangeError("pollIntervalMs must be an integer between 1 and 2147483647, got 0"),
            ],
            [
                "a fractional poll interval",
                { pollIntervalMs: 1.5 },
                MASTER_SEED,
                new RangeError("pollIntervalMs must be an integer between 1 and 2147483647, got 1.5"),
            ],
            [
                "a poll interval past the timer ceiling",
                { pollIntervalMs: 2 ** 31 },
                MASTER_SEED,
                new RangeError("pollIntervalMs must be an integer between 1 and 2147483647, got 2147483648"),
            ],
            [
                "an unknown network",
                { network: "devnet" as unknown as "testnet" },
                MASTER_SEED,
                new TypeError("network must be one of mainnet, testnet"),
            ],
            [
                "a development chain with a short code hash",
                { network: { ...DEV_NETWORK, commitmentLock: { ...DEV_NETWORK.commitmentLock, codeHash: new Uint8Array(31) } } },
                MASTER_SEED,
                new TypeError("network.commitmentLock.codeHash must be 32 bytes, got 31"),
            ],
            [
                "a development chain with an unknown currency",
                { network: { ...DEV_NETWORK, invoiceCurrency: "Fibx" as unknown as "Fibd" } },
                MASTER_SEED,
                new TypeError("network.invoiceCurrency must be one of Fibb, Fibt, Fibd"),
            ],
            [
                "a development chain without a funding lock cell deps count",
                { network: { ...DEV_NETWORK, fundingLockCellDepsCount: undefined as unknown as number } },
                MASTER_SEED,
                new RangeError("network.fundingLockCellDepsCount must be an integer between 1 and 255, got undefined"),
            ],
            [
                "a nonce reuse mode in another case",
                { nonceReuse: "ALLOW" as never },
                MASTER_SEED,
                new TypeError("options.nonceReuse must be one of refuse, allow"),
            ],
            [
                "a null nonce reuse mode",
                { nonceReuse: null as never },
                MASTER_SEED,
                new TypeError("options.nonceReuse must be one of refuse, allow"),
            ],
            [
                "a nonce reuse mode that is a number",
                { nonceReuse: 1 as never },
                MASTER_SEED,
                new TypeError("options.nonceReuse must be one of refuse, allow"),
            ],
            [
                "a watchtower approval that is not an object",
                { watchtower: "approve" as never },
                MASTER_SEED,
                new TypeError("options.watchtower must be an object"),
            ],
            [
                "a token with a space",
                { biscuitToken: "not a token" },
                MASTER_SEED,
                new TypeError("token must be printable ASCII without spaces"),
            ],
        ])("refuses %s", (_, overrides, seed, error) => {
            expect(() => harness(overrides, seed)).toThrow(error);
        });

        it("refuses the options themselves when they are not an object", () => {
            expect(() => new FiberLspSdk(MASTER_SEED, undefined as never)).toThrow(new TypeError("options must be an object"));
        });

        it("checks the seed before anything else", () => {
            expect(() => harness({ rpcUrl: "", storage: undefined }, new Uint8Array(31))).toThrow(
                new TypeError("masterSeed must be 32 bytes, got 31"),
            );
        });

        it.each([
            ["the default poll interval", { pollIntervalMs: undefined }],
            ["a poll interval at the timer ceiling", { pollIntervalMs: 2 ** 31 - 1 }],
            ["no token", { biscuitToken: undefined }],
            ["the mainnet preset", { network: "mainnet" as const }],
            ["a development chain", { network: DEV_NETWORK }],
            ["no clock", { now: undefined }],
            ["no nonce reuse mode", { nonceReuse: undefined }],
            ["nonce reuse refused", { nonceReuse: "refuse" as const }],
            ["nonce reuse allowed", { nonceReuse: "allow" as const }],
            ["no watchtower approval", { watchtower: undefined }],
            ["the vectors' watchtower approval", { watchtower: APPROVAL }],
        ])("accepts %s", (_, overrides) => {
            expect(() => harness(overrides)).not.toThrow();
        });

        it("gives every poll step thirty seconds before it is reported and the tick moves on", () => {
            const h = harness();
            expect(POLL_STEP_TIMEOUT_MS).toBe(30_000);
            expect((contextOf(h.sdk).poller as unknown as { stepTimeoutMs: number }).stepTimeoutMs).toBe(POLL_STEP_TIMEOUT_MS);
        });

        it("refuses to default the timer when the runtime has none", () => {
            expect(() => withRuntime({ setTimeout: undefined }, () => harness({ timer: undefined }))).toThrow(
                new TypeError("this runtime has no timer: pass one in the options"),
            );
        });

        it("defaults fetch to the runtime's, and refuses to when the runtime has none", () => {
            expect(() => withRuntime({ fetch: () => undefined }, () => harness({ fetch: undefined }))).not.toThrow();
            expect(() => withRuntime({ fetch: undefined }, () => harness({ fetch: undefined }))).toThrow(
                new TypeError("this runtime has no fetch: pass one in the options"),
            );
        });
    });

    describe("onEvent()", () => {
        it.each([
            ["undefined", undefined],
            ["an object", { onEvent: () => undefined }],
        ])("refuses a listener that is %s, which would fail every delivery unheard", (_, listener) => {
            const h = harness();
            expect(() => h.sdk.onEvent(listener as never)).toThrow(new TypeError("listener must be a function"));
        });
    });

    describe("wiring", () => {
        it.each([
            ["testnet", COMMITMENT_LOCK_TESTNET],
            ["mainnet", COMMITMENT_LOCK_MAINNET],
        ] as const)("resolves the %s preset's commitment lock", (network, lock) => {
            expect(contextOf(harness({ network }).sdk).network.commitmentLock).toBe(lock);
        });

        it("keeps a copy of a development chain's network", () => {
            const h = harness({ network: DEV_NETWORK });
            expect(contextOf(h.sdk).network).toEqual(DEV_NETWORK);
            expect(contextOf(h.sdk).network.commitmentLock).not.toBe(DEV_NETWORK.commitmentLock);
        });

        it.each(["testnet", "mainnet"] as const)("takes the %s funding lock's two cell deps from the preset", (network) => {
            expect(contextOf(harness({ network }).sdk).network.fundingLockCellDepsCount).toBe(2);
        });

        it("sends the rpc through the host's fetch, to the rpc url, under the token", async () => {
            const h = harness();
            h.fetch.answer({ rejection: new Error("offline") });
            await rejection(contextOf(h.sdk).rpc.listChannels());
            expect(h.fetch.requests).toHaveLength(1);
            expect(h.fetch.last.url).toBe(RPC_URL);
            expect(h.fetch.last.init.headers).toEqual({ "content-type": "application/json", authorization: `Bearer ${TOKEN}` });
        });

        it("sends the rpc without an authorization header when there is no token", async () => {
            const h = harness({ biscuitToken: undefined });
            h.fetch.answer({ rejection: new Error("offline") });
            await rejection(contextOf(h.sdk).rpc.listChannels());
            expect(h.fetch.last.init.headers).toEqual({ "content-type": "application/json" });
        });

        it("keeps the allocator's and the activity's records in the host's storage", async () => {
            const h = harness();
            await contextOf(h.sdk).allocator.allocateChannelIndex();
            await contextOf(h.sdk).activity.watch("channel", CHANNEL_ID);
            expect([...h.storage.map.keys()]).toEqual(["fiber-lsp-sdk:allocator:channel", "fiber-lsp-sdk:activity"]);
        });

        it("hands the poller the facade's own emit, so what a tick reports reaches the listeners", () => {
            const h = harness();
            const emit = (contextOf(h.sdk).poller as unknown as { emit: (event: SdkEvent) => void }).emit;
            const error = new SdkError("poll_failed", "the node could not be read");
            emit({ type: "ERROR", error });
            expect(h.errors()).toEqual([error]);
        });

        it("copies the LSP key, so the host's bytes cannot move under the device", () => {
            const lspPubkey = Uint8Array.from(LSP_PUBKEY);
            const h = harness({ lspPubkey });
            lspPubkey.fill(0);
            expect(contextOf(h.sdk).lspPubkey).toEqual(LSP_PUBKEY);
        });

        it("hands the policy engine a copy of the watchtower approval, and none without one", () => {
            const watchtowerOf = (sdk: FiberLspSdk): unknown => (contextOf(sdk).policy as unknown as { watchtower: unknown }).watchtower;
            const approval = structuredClone(APPROVAL);
            const h = harness({ watchtower: approval });
            approval.destination.args.fill(0);
            expect(watchtowerOf(h.sdk)).toEqual(APPROVAL);
            expect(watchtowerOf(harness().sdk)).toBeNull();
        });

        it("reads the clock from the options, and from Date.now without one", () => {
            const now = (): number => NOW_MS;
            expect(contextOf(harness({ now }).sdk).now).toBe(now);
            expect(contextOf(harness({ now: undefined }).sdk).now).toBe(Date.now);
        });
    });

    describe("construction defaults", () => {
        it("defaults the poll interval to five seconds", async () => {
            const h = harness({ pollIntervalMs: undefined });
            h.sdk.connect();
            await flush();
            expect(DEFAULT_POLL_INTERVAL_MS).toBe(5_000);
            expect(h.timer.delays).toContain(DEFAULT_POLL_INTERVAL_MS);
        });

        it("defaults the timer to the runtime's, read once at construction", async () => {
            const delays: number[] = [];
            const runtime = {
                setTimeout: function (this: unknown, _callback: () => void, delayMs: number) {
                    delays.push(delayMs);
                    return { delayMs };
                },
                clearTimeout: () => undefined,
            };
            const h = withRuntime(runtime, () => harness({ timer: undefined }));
            const later = {
                setTimeout: () => {
                    throw new Error("read again");
                },
                clearTimeout: () => {
                    throw new Error("read again");
                },
            };
            withRuntime(later, () => h.sdk.connect());
            await flush();
            expect(delays).toEqual([POLL_STEP_TIMEOUT_MS, POLL_STEP_TIMEOUT_MS, POLL_INTERVAL_MS]);
            withRuntime(later, () => h.sdk.disconnect());
        });
    });

    describe("connect() and the poller", () => {
        it("ticks when connect() is called, and then at the interval", async () => {
            const h = harness();
            h.sdk.connect();
            expect(h.timer.delays).toEqual([POLL_STEP_TIMEOUT_MS]);
            await flush();
            // Each step lists the node's channels.
            expect(h.polls()).toBe(1);
            expect(h.fetch.requests).toHaveLength(2);
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(2);
            expect(h.fetch.requests).toHaveLength(4);
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(3);
            expect(h.fetch.requests).toHaveLength(6);
        });

        it("starts nothing twice when called while polling", async () => {
            const h = harness();
            h.sdk.connect();
            await flush();
            h.sdk.connect();
            await flush();
            expect(h.polls()).toBe(1);
            expect(h.timer.pending).toBe(1);
        });

        it("stops at disconnect(), leaving no timer behind", async () => {
            const h = harness();
            h.sdk.connect();
            await flush();
            expect(h.timer.pending).toBe(1);
            h.sdk.disconnect();
            expect(h.timer.pending).toBe(0);
            h.timer.advance(POLL_INTERVAL_MS * 3);
            await flush();
            expect(h.polls()).toBe(1);
        });

        it("starts over at the next connect()", async () => {
            const h = harness();
            h.sdk.connect();
            await flush();
            h.sdk.disconnect();
            h.sdk.connect();
            await flush();
            expect(h.polls()).toBe(2);
            expect(h.timer.pending).toBe(1);
        });

        it("is a no-op to disconnect() before any connect(), and idempotent after one", async () => {
            const h = harness();
            expect(() => h.sdk.disconnect()).not.toThrow();
            expect(h.events).toEqual([]);
            h.sdk.connect();
            h.sdk.disconnect();
            expect(() => h.sdk.disconnect()).not.toThrow();
            expect(h.timer.pending).toBe(0);
        });

        it("disconnects without throwing when the host's cancel does", () => {
            const timer = new TimerMock();
            const throwing = {
                schedule: (callback: () => void, delayMs: number) => {
                    const cancel = timer.schedule(callback, delayMs);
                    return () => {
                        cancel();
                        throw new Error("cancel broke");
                    };
                },
            };
            const h = harness({ timer: throwing });
            h.sdk.connect();
            expect(() => h.sdk.disconnect()).not.toThrow();
        });
    });

    describe("signing", () => {
        const sent = signingCaseOf(signing, "SendCommitmentSigned");
        const vectorsChain = {
            commitmentLock: signingCommitmentLock(signing),
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: signing.channel.funding_lock_cell_deps_count,
        } as const;

        it("answers a signing request at the first tick of connect(), submitting the vectors' signature", async () => {
            // The vectors are signed on testnet's network.
            expect(vectorsChain.commitmentLock).toEqual(COMMITMENT_LOCK_TESTNET);
            expect(vectorsChain.fundingLockCellDepsCount).toBe(2);
            const h = await signingHarness({ network: "testnet" });
            await tickOver(h, sent.result.status, true);
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(SIGNING_CHANNEL_ID),
                signatureSubmissionCall(signing, sent),
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(SIGNING_CHANNEL_ID),
            ]);
            expect(h.events).toStrictEqual([signedEventOf(signing, sent)]);
        });

        it("signs on a development chain with the vectors' network", async () => {
            const h = await signingHarness({ network: vectorsChain });
            await tickOver(h, sent.result.status, true);
            expect(h.events).toStrictEqual([signedEventOf(signing, sent)]);
        });

        it("signs over its copy of a development chain's code hash, whatever the host does to its bytes", async () => {
            const codeHash = Uint8Array.from(vectorsChain.commitmentLock.codeHash);
            const h = await signingHarness({ network: { ...vectorsChain, commitmentLock: { ...vectorsChain.commitmentLock, codeHash } } });
            codeHash.fill(0);
            await tickOver(h, sent.result.status, true);
            expect(h.events).toStrictEqual([signedEventOf(signing, sent)]);
        });

        it("refuses a commitment under another network's commitment lock, submitting nothing", async () => {
            const h = await signingHarness({ network: "mainnet" });
            await tickOver(h, sent.result.status, false);
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(SIGNING_CHANNEL_ID),
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(SIGNING_CHANNEL_ID),
            ]);
            expect(h.events).toStrictEqual([
                refusedEvent("SendCommitmentSigned", {
                    code: "malformed",
                    message: "the message does not match the attached channel state",
                }),
            ]);
        });

        it("refuses a commitment under another funding lock cell deps count, submitting nothing", async () => {
            const h = await signingHarness({
                network: { ...vectorsChain, fundingLockCellDepsCount: vectorsChain.fundingLockCellDepsCount + 1 },
            });
            await tickOver(h, sent.result.status, false);
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(SIGNING_CHANNEL_ID),
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(SIGNING_CHANNEL_ID),
            ]);
            expect(h.events).toStrictEqual([
                refusedEvent("SendCommitmentSigned", {
                    code: "malformed",
                    message: "the message does not match the attached channel state",
                }),
            ]);
        });

        // Signs the slot's first session before the facade is built, so its first tick serves the second.
        async function servedSlot(overrides: Partial<FiberLspSdkOptions>): Promise<SigningHarness> {
            return signingHarness(overrides, async (channel) => {
                await stageSecondSession(signing, channel);
                const first = await channel.dispatch.handle(SIGNING_CHANNEL_ID, signingStatusField(sent));
                if (first.kind !== "signed") throw new Error(`the slot's first session was ${first.kind}`);
            });
        }

        it("serves a second session on a served slot under nonceReuse allow, as a warning", async () => {
            const h = await servedSlot({ nonceReuse: "allow" });
            const second = secondSessionStatus(signing);
            await tickOver(h, second.value, true);
            expect(h.node.calls().map((call) => call.method)).toEqual([
                "list_channels",
                "get_channel_signing_status",
                "submit_channel_signature",
                "list_channels",
                "get_watchtower_signing_status",
            ]);
            expect(h.events).toStrictEqual([signedEventOf(signing, signingCaseOf(signing, "CompleteReceivedCommitment"), "warning")]);
        });

        it.each([
            ["by default", {}],
            ["under nonceReuse refuse", { nonceReuse: "refuse" as const }],
        ])("refuses a second session on a served slot %s", async (_, overrides) => {
            const h = await servedSlot(overrides);
            await tickOver(h, secondSessionStatus(signing).value, false);
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(SIGNING_CHANNEL_ID),
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(SIGNING_CHANNEL_ID),
            ]);
            expect(h.events).toStrictEqual([
                refusedEvent("CompleteReceivedCommitment", {
                    code: "policy_refusal",
                    message: "slot COMMITMENT:4 has already served a different signing session",
                }),
            ]);
        });
    });

    describe("watchtower signing", () => {
        const sent = signingCaseOf(signing, "SendCommitmentSigned");
        const spend = watchtowerSpendOf(signing, "own commitment: settlement");
        const spendStatus = watchtowerStatusField(spend).value;
        const purpose = { kind: "settlement" } as const;

        it("runs after the channel signing step, in the same tick, over the channels the node lists", async () => {
            const h = await signingHarness({ watchtower: APPROVAL });
            await tickOver(h, IDLE, false);
            expect(h.node.calls()).toEqual([
                LIST_CHANNELS_CALL,
                signingStatusCall(SIGNING_CHANNEL_ID),
                LIST_CHANNELS_WITH_CLOSED_CALL,
                watchtowerStatusCall(SIGNING_CHANNEL_ID),
            ]);
            expect(h.events).toEqual([]);
        });

        it("runs after a channel signing step that signed, emitting each step's event in the order of the steps", async () => {
            const h = await signingHarness({});
            await tickOver(h, sent.result.status, true, spendStatus);
            expect(h.events.map((event) => event.type)).toEqual(["SIGNING", "WATCHTOWER_SIGNING"]);
        });

        it("runs even when the channel signing step fails", async () => {
            const h = await signingHarness({});
            h.node
                .error(-32000, "node is syncing")
                .result({ channels: [{ channel_id: SIGNING_CHANNEL_ID, state: READY }] })
                .result({ channel_id: SIGNING_CHANNEL_ID, status: IDLE });
            h.sdk.connect();
            await flush();
            h.sdk.disconnect();
            expect(h.node.calls()).toEqual([LIST_CHANNELS_CALL, LIST_CHANNELS_WITH_CLOSED_CALL, watchtowerStatusCall(SIGNING_CHANNEL_ID)]);
            expect(h.events.map((event) => event.type)).toEqual(["ERROR"]);
        });

        it("refuses every spend without the host's approval, submitting nothing", async () => {
            const h = await signingHarness({});
            await tickOver(h, IDLE, false, spendStatus);
            expect(h.node.calls().at(-1)).toEqual(watchtowerStatusCall(SIGNING_CHANNEL_ID));
            expect(h.events).toStrictEqual([
                {
                    type: "WATCHTOWER_SIGNING",
                    channelId: SIGNING_CHANNEL_ID,
                    requestId: spend.request_id,
                    purpose,
                    outcome: "refused",
                    error: {
                        code: "policy_refusal",
                        message: "watchtower option: the host approved no destination, so the device signs no watchtower spend",
                    },
                },
            ]);
        });

        it("judges a spend by the host's approval when given one", async () => {
            const h = await signingHarness({ watchtower: APPROVAL });
            await tickOver(h, IDLE, false, spendStatus);
            expect(h.node.calls().at(-1)).toEqual(watchtowerStatusCall(SIGNING_CHANNEL_ID));
            expect(h.events).toStrictEqual([
                {
                    type: "WATCHTOWER_SIGNING",
                    channelId: SIGNING_CHANNEL_ID,
                    requestId: spend.request_id,
                    purpose,
                    outcome: "refused",
                    error: {
                        code: "policy_refusal",
                        message:
                            "watchtower source: input 0, spent with a zero since, is no cell descending from a signed commitment: no " +
                            "commitment has been signed",
                    },
                },
            ]);
        });
    });

    describe("events", () => {
        it("reaches every listener, a throwing one included, and stops at an unsubscribe", () => {
            const h = harness();
            const seen: string[] = [];
            const unsubscribe = h.sdk.onEvent((event) => {
                seen.push(`first ${event.type}`);
                throw new Error("listener broke");
            });
            h.sdk.onEvent((event) => seen.push(`second ${event.type}`));
            const error = new SdkError("poll_failed", "the node could not be read");
            contextOf(h.sdk).emit({ type: "ERROR", error });
            expect(seen).toEqual(["first ERROR", "second ERROR"]);
            unsubscribe();
            contextOf(h.sdk).emit({ type: "ERROR", error });
            expect(seen.slice(2)).toEqual(["second ERROR"]);
        });

        it("delivers an event to the listeners subscribed when it is raised, not to one added on hearing it", () => {
            const h = harness();
            const seen: SdkEvent[] = [];
            let added = false;
            h.sdk.onEvent(() => {
                if (added) return;
                added = true;
                h.sdk.onEvent((event) => seen.push(event));
            });
            const first: SdkEvent = { type: "ERROR", error: new SdkError("poll_failed", "first") };
            const second: SdkEvent = { type: "ERROR", error: new SdkError("poll_failed", "second") };
            contextOf(h.sdk).emit(first);
            expect(seen).toEqual([]);
            contextOf(h.sdk).emit(second);
            expect(seen).toEqual([second]);
        });
    });
});
