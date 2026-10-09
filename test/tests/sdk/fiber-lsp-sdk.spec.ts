import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import type { FiberLspSdkOptions, SdkContext, SdkEvent } from "../../../src/sdk";
import { FiberLspSdk, POLL_STEP_TIMEOUT_MS, SdkError } from "../../../src/sdk";
import { FetchMock } from "../../mocks/rpc";
import { InMemorySignerStorage } from "../../mocks/policy";
import { TimerMock, WebSocketFactoryMock } from "../../mocks/session";
import { loadInteropVectors } from "../../utils/interop-vectors";
import { rejection } from "../../utils/rejection";
import { withRuntime } from "../../utils/with-runtime";

const vectors = loadInteropVectors();
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const PEER_KEYS = deriveChannelKeys(hexToBytes(vectors.digest.remote.seed));
const LSP_PUBKEY = pubkeyOf(PEER_KEYS.fundingKey);
const RPC_URL = "http://fiber.example:8227";
const SESSION_URL = "wss://lsp.example/signer";
const TOKEN = "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiDs-token_example=";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const POLL_INTERVAL_MS = 7_000;
const NOW_MS = 1_791_367_200_250;
const DEV_NETWORK = { commitmentLock: { codeHash: new Uint8Array(32).fill(0x5d), hashType: "data1" }, invoiceCurrency: "Fibd" } as const;

function harness(overrides: Partial<FiberLspSdkOptions> = {}, seed: Uint8Array = MASTER_SEED) {
    const sockets = new WebSocketFactoryMock();
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    const fetch = new FetchMock();
    const events: SdkEvent[] = [];
    const sdk = new FiberLspSdk(seed, {
        network: "testnet",
        storage,
        webSocketFactory: sockets.create,
        rpcUrl: RPC_URL,
        signerSessionUrl: SESSION_URL,
        biscuitToken: TOKEN,
        lspPubkey: LSP_PUBKEY,
        fetch: fetch.fetch,
        timer,
        now: () => NOW_MS,
        pollIntervalMs: POLL_INTERVAL_MS,
        session: { heartbeatIntervalMs: 0 },
        ...overrides,
    });
    sdk.onEvent((event) => events.push(event));
    const errors = (): SdkError[] => events.flatMap((event) => (event.type === "ERROR" ? [event.error] : []));
    return { sdk, sockets, timer, storage, fetch, events, errors };
}

// Read through the private context until the operations observe the wiring.
function contextOf(sdk: FiberLspSdk): SdkContext {
    return (sdk as unknown as { context: SdkContext }).context;
}

function dispatchLockOf(sdk: FiberLspSdk): unknown {
    return (contextOf(sdk).dispatch as unknown as { commitmentLock: unknown }).commitmentLock;
}

describe("FiberLspSdk", () => {
    describe("construction", () => {
        it("connects nothing and schedules nothing until connect()", () => {
            const h = harness();
            expect(h.sockets.sockets).toEqual([]);
            expect(h.timer.pending).toBe(0);
            expect(h.fetch.requests).toEqual([]);
            expect(h.storage.ops).toEqual([]);
            expect(h.sdk.sessionState).toBe("idle");
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
            ["no socket factory", { webSocketFactory: undefined }, MASTER_SEED, new TypeError("webSocketFactory must be a function")],
            ["a fetch that is not a function", { fetch: "fetch" as never }, MASTER_SEED, new TypeError("fetch must be a function")],
            ["a clock that is not a function", { now: 1_791_367_200_250 as never }, MASTER_SEED, new TypeError("now must be a function")],
            ["a timer that is not an object", { timer: (() => undefined) as never }, MASTER_SEED, new TypeError("timer must be an object")],
            ["a timer without schedule", { timer: {} as never }, MASTER_SEED, new TypeError("timer.schedule must be a function")],
            [
                "session options that are not an object",
                { session: 5_000 as never },
                MASTER_SEED,
                new TypeError("session must be an object"),
            ],
            [
                "a reconnect policy that is not an object",
                { session: { reconnect: "abc" as never } },
                MASTER_SEED,
                new TypeError("reconnect must be an object"),
            ],
            ["a null token", { biscuitToken: null as never }, MASTER_SEED, new TypeError("token must be printable ASCII without spaces")],
            ["an empty rpc url", { rpcUrl: "" }, MASTER_SEED, new TypeError("rpcUrl must be a non-empty string")],
            ["an empty session url", { signerSessionUrl: "" }, MASTER_SEED, new TypeError("signerSessionUrl must be a non-empty string")],
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
            ["null session options", { session: null as never }, MASTER_SEED, new TypeError("session must be an object")],
            [
                "a null reconnect policy",
                { session: { reconnect: null as never } },
                MASTER_SEED,
                new TypeError("reconnect must be an object"),
            ],
            [
                "a null connect timeout",
                { session: { connectTimeoutMs: null as never } },
                MASTER_SEED,
                new RangeError("connectTimeoutMs must be an integer between 1 and 2147483647, got null"),
            ],
            [
                "a null heartbeat interval",
                { session: { heartbeatIntervalMs: null as never } },
                MASTER_SEED,
                new RangeError("heartbeatIntervalMs must be an integer between 0 and 2147483647, got null"),
            ],
            [
                "a null heartbeat timeout",
                { session: { heartbeatTimeoutMs: null as never } },
                MASTER_SEED,
                new RangeError("heartbeatTimeoutMs must be an integer between 1 and 2147483647, got null"),
            ],
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
                "a token with a space",
                { biscuitToken: "not a token" },
                MASTER_SEED,
                new TypeError("token must be printable ASCII without spaces"),
            ],
            [
                "a session connect timeout of 0",
                { session: { connectTimeoutMs: 0 } },
                MASTER_SEED,
                new RangeError("connectTimeoutMs must be an integer between 1 and 2147483647, got 0"),
            ],
            [
                "a session heartbeat timeout of 0",
                { session: { heartbeatTimeoutMs: 0 } },
                MASTER_SEED,
                new RangeError("heartbeatTimeoutMs must be an integer between 1 and 2147483647, got 0"),
            ],
            [
                "a reconnect factor below 1",
                { session: { reconnect: { factor: 0.5 } } },
                MASTER_SEED,
                new RangeError("reconnect.factor must be a finite number of at least 1, got 0.5"),
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
            ["no session options", { session: undefined }],
            ["no clock", { now: undefined }],
            ["a reconnect policy with a field given as undefined", { session: { reconnect: { maxDelayMs: undefined } } }],
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
        ] as const)("hands the %s commitment lock to the dispatch", (network, lock) => {
            const h = harness({ network });
            expect(dispatchLockOf(h.sdk)).toBe(lock);
            expect(contextOf(h.sdk).network.commitmentLock).toBe(lock);
        });

        it("hands a development chain's commitment lock to the dispatch as a copy", () => {
            const h = harness({ network: DEV_NETWORK });
            expect(dispatchLockOf(h.sdk)).toEqual(DEV_NETWORK.commitmentLock);
            expect(dispatchLockOf(h.sdk)).not.toBe(DEV_NETWORK.commitmentLock);
            expect(contextOf(h.sdk).network.invoiceCurrency).toBe("Fibd");
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

        it("reads the clock from the options, and from Date.now without one", () => {
            const now = (): number => NOW_MS;
            expect(contextOf(harness({ now }).sdk).now).toBe(now);
            expect(contextOf(harness({ now: undefined }).sdk).now).toBe(Date.now);
        });
    });
});
