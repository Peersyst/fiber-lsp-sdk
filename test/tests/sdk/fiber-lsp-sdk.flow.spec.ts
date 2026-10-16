import { hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import type { FiberLspSdkOptions, SdkEvent } from "../../../src/sdk";
import { DEFAULT_POLL_INTERVAL_MS, FiberLspSdk, SdkError } from "../../../src/sdk";
import type { SessionState } from "../../../src/session";
import { DEFAULT_HEARTBEAT_INTERVAL_MS, DEFAULT_SESSION_CONNECT_TIMEOUT_MS, SessionError } from "../../../src/session";
import { WalletIdentity } from "../../../src/signer";
import { FetchMock } from "../../mocks/rpc";
import { InMemorySignerStorage } from "../../mocks/policy";
import { TimerMock } from "../../mocks/session";
import { flush } from "../../utils/flush";
import { loadInteropVectors } from "../../utils/interop-vectors";
import { rejection } from "../../utils/rejection";
import { withRuntime } from "../../utils/with-runtime";
import { InMemorySignerBridge } from "../../utils/signer-bridge";

const vectors = loadInteropVectors();
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const PEER_KEYS = deriveChannelKeys(hexToBytes(vectors.digest.remote.seed));
const LSP_PUBKEY = pubkeyOf(PEER_KEYS.fundingKey);
const IDENTITY = new WalletIdentity(MASTER_SEED);
const RPC_URL = "http://fiber.example:8227";
const SESSION_URL = "wss://lsp.example/signer";
const TOKEN = "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiDs-token_example=";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const POLL_INTERVAL_MS = 7_000;
const NOW_MS = 1_791_367_200_250;

function harness(overrides: Partial<FiberLspSdkOptions> = {}, seed: Uint8Array = MASTER_SEED) {
    const bridge = new InMemorySignerBridge(PEER_KEYS);
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    const fetch = new FetchMock();
    const events: SdkEvent[] = [];
    const sdk = new FiberLspSdk(seed, {
        network: "testnet",
        storage,
        webSocketFactory: bridge.createWebSocket,
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
    const states = (): SessionState[] => events.flatMap((event) => (event.type === "SESSION" ? [event.state] : []));
    const errors = (): SdkError[] => events.flatMap((event) => (event.type === "ERROR" ? [event.error] : []));
    const polls = (): number => timer.delays.filter((delay) => delay === POLL_INTERVAL_MS).length;
    return { sdk, bridge, timer, storage, fetch, events, states, errors, polls };
}

function sdkError(error: unknown, code: SdkError["code"]): SdkError {
    expect(error).toBeInstanceOf(SdkError);
    expect((error as SdkError).code).toBe(code);
    return error as SdkError;
}

describe("FiberLspSdk against the LSP double", () => {
    describe("construction", () => {
        it("hands the session its four timings and nothing else of the object they came in", async () => {
            const random = jest.fn(() => 0.5);
            const h = harness({ session: { heartbeatIntervalMs: 0, random } as never });
            await h.sdk.connect();
            h.bridge.dropConnection();
            await flush();
            expect(h.sdk.sessionState).toBe("reconnecting");
            expect(random).not.toHaveBeenCalled();
            h.sdk.disconnect();
        });

        it("defaults the poll interval to five seconds", async () => {
            const h = harness({ pollIntervalMs: undefined });
            await h.sdk.connect();
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
            await withRuntime(later, () => h.sdk.connect());
            expect(delays).toEqual([POLL_INTERVAL_MS, DEFAULT_SESSION_CONNECT_TIMEOUT_MS]);
            withRuntime(later, () => h.sdk.disconnect());
        });
    });

    describe("connect()", () => {
        it("establishes the session under the wallet identity, which the bridge verifies and pins", async () => {
            const h = harness();
            await h.sdk.connect();
            expect(h.bridge.hasSession).toBe(true);
            expect(h.bridge.identityKey).toEqual(IDENTITY.publicKey);
            expect(h.bridge.factory.last.url).toBe(SESSION_URL);
            expect(h.sdk.sessionState).toBe("established");
            expect(h.states()).toEqual(["connecting", "authenticating", "established"]);
            expect(h.errors()).toEqual([]);
        });

        it("answers the node's requests through the dispatch over the policy: an unknown channel is refused as such", async () => {
            const h = harness();
            await h.sdk.connect();
            await expect(h.bridge.request(CHANNEL_ID, { method: "get_base_public_keys", params: {} })).resolves.toEqual({
                error: { code: "unknown_channel", message: `channel ${CHANNEL_ID} is not registered on this device` },
            });
            expect(h.bridge.violations).toEqual([]);
        });

        it("reports the device's own fault while answering, a storage that throws, as an ERROR, leaving the request unanswered", async () => {
            const cause = new Error("disk unavailable");
            const backing = new InMemorySignerStorage();
            let broken = false;
            const storage = {
                get: (key: string) => {
                    if (broken) throw cause;
                    return backing.get(key);
                },
                set: (key: string, value: string) => backing.set(key, value),
            };
            const h = harness({ storage });
            await h.sdk.connect();
            broken = true;
            let answered = false;
            void h.bridge.request(CHANNEL_ID, { method: "get_base_public_keys", params: {} }).then(() => {
                answered = true;
            });
            await flush();
            expect(answered).toBe(false);
            expect(h.errors()).toHaveLength(1);
            expect(h.errors()[0]?.code).toBe("session_error");
            expect(h.errors()[0]?.cause).toBe(cause);
            expect(h.errors()[0]?.message).toBe("the signer session reported an error: disk unavailable");
            expect(h.sdk.sessionState).toBe("established");
            h.sdk.disconnect();
        });

        it("signs the challenge with the device's own identity: another seed is another identity", async () => {
            const other = harness({}, new Uint8Array(32).fill(0x42));
            await other.sdk.connect();
            expect(other.bridge.identityKey).not.toEqual(IDENTITY.publicKey);
        });

        it("resolves at once when already established, opening no second socket", async () => {
            const h = harness();
            await h.sdk.connect();
            await h.sdk.connect();
            expect(h.bridge.factory.sockets).toHaveLength(1);
            expect(h.states()).toEqual(["connecting", "authenticating", "established"]);
        });

        it("rejects as connect_failed, with the session's refusal underneath, when the bridge refuses the identity", async () => {
            const h = harness();
            h.bridge.identityKey = new Uint8Array(32).fill(0x11);
            const error = sdkError(await rejection(h.sdk.connect()), "connect_failed");
            expect(error.cause).toBeInstanceOf(SessionError);
            expect((error.cause as SessionError).kind).toBe("handshake_refused");
            expect(error.message).toBe(
                `the signer session could not be established (handshake_refused): ${(error.cause as SessionError).message}`,
            );
            expect(h.sdk.sessionState).toBe("closed");
            expect(h.states()).toEqual(["connecting", "authenticating", "closed"]);
        });

        it("rejects as connect_failed on another protocol version", async () => {
            const h = harness();
            h.bridge.protocolVersion = 2;
            const error = sdkError(await rejection(h.sdk.connect()), "connect_failed");
            expect((error.cause as SessionError).kind).toBe("version_mismatch");
        });

        it("rejects as connect_failed when disconnect() comes first", async () => {
            const h = harness();
            const pending = h.sdk.connect();
            h.sdk.disconnect();
            const error = sdkError(await rejection(pending), "connect_failed");
            expect((error.cause as SessionError).kind).toBe("disconnected");
            expect(h.sdk.sessionState).toBe("closed");
            expect(h.timer.pending).toBe(0);
        });

        it("reports the session's fatal failure as an ERROR event too, since a listener may not be the caller", async () => {
            const h = harness();
            h.bridge.protocolVersion = 2;
            await rejection(h.sdk.connect());
            expect(h.errors().map((error) => error.code)).toEqual(["session_error"]);
            expect((h.errors()[0]?.cause as SessionError).kind).toBe("version_mismatch");
        });

        it("connects again after disconnect(), under the identity the bridge pinned", async () => {
            const h = harness();
            await h.sdk.connect();
            h.sdk.disconnect();
            await h.sdk.connect();
            expect(h.bridge.factory.sockets).toHaveLength(2);
            expect(h.bridge.hasSession).toBe(true);
            expect(h.sdk.sessionState).toBe("established");
        });

        it("connects again after a refused handshake once the bridge accepts", async () => {
            const h = harness();
            h.bridge.identityKey = new Uint8Array(32).fill(0x11);
            await rejection(h.sdk.connect());
            h.bridge.identityKey = undefined;
            await h.sdk.connect();
            expect(h.sdk.sessionState).toBe("established");
        });

        it("cuts the reconnect backoff short when called from reconnecting, as a host does on foreground", async () => {
            const h = harness();
            await h.sdk.connect();
            h.bridge.dropConnection();
            await flush();
            expect(h.sdk.sessionState).toBe("reconnecting");
            expect(h.states().at(-1)).toBe("reconnecting");
            expect(h.timer.pending).toBe(2);
            await h.sdk.connect();
            expect(h.sdk.sessionState).toBe("established");
            expect(h.bridge.factory.sockets).toHaveLength(2);
        });
    });

    describe("the poller", () => {
        it("ticks when connect() is called, before the session is established, and then at the interval", async () => {
            const h = harness();
            const pending = h.sdk.connect();
            expect(h.timer.delays).toEqual([POLL_INTERVAL_MS, DEFAULT_SESSION_CONNECT_TIMEOUT_MS]);
            await pending;
            expect(h.polls()).toBe(1);
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(2);
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(3);
        });

        it("keeps ticking while the session reconnects against a bridge that is down", async () => {
            const h = harness();
            await h.sdk.connect();
            h.bridge.factory.failure = new Error("bridge down");
            h.bridge.dropConnection();
            await flush();
            expect(h.sdk.sessionState).toBe("reconnecting");
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(2);
            expect(h.sdk.sessionState).toBe("reconnecting");
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(3);
            expect(h.bridge.hasSession).toBe(false);
        });

        it("keeps ticking after a rejected connect(), until disconnect()", async () => {
            const h = harness();
            h.bridge.protocolVersion = 2;
            await rejection(h.sdk.connect());
            expect(h.timer.pending).toBe(1);
            h.timer.advance(POLL_INTERVAL_MS);
            await flush();
            expect(h.polls()).toBe(2);
            h.sdk.disconnect();
            expect(h.timer.pending).toBe(0);
        });

        it("stops at disconnect(), leaving no timer behind", async () => {
            const h = harness({ session: { heartbeatIntervalMs: DEFAULT_HEARTBEAT_INTERVAL_MS } });
            await h.sdk.connect();
            expect(h.timer.pending).toBe(2);
            h.sdk.disconnect();
            expect(h.timer.pending).toBe(0);
            h.timer.advance(POLL_INTERVAL_MS * 3);
            await flush();
            expect(h.polls()).toBe(1);
        });

        it("starts over at the next connect()", async () => {
            const h = harness();
            await h.sdk.connect();
            h.sdk.disconnect();
            await h.sdk.connect();
            expect(h.polls()).toBe(2);
            expect(h.timer.pending).toBe(1);
        });
    });

    describe("disconnect()", () => {
        it("lets a listener that connects again on the closed state find polling running, as the stop comes first", async () => {
            const h = harness();
            await h.sdk.connect();
            let reconnecting: Promise<void> | undefined;
            h.sdk.onEvent((event) => {
                if (event.type === "SESSION" && event.state === "closed" && !reconnecting) reconnecting = h.sdk.connect();
            });
            h.sdk.disconnect();
            await reconnecting;
            expect(h.sdk.sessionState).toBe("established");
            expect(h.timer.pendingDelays).toContain(POLL_INTERVAL_MS);
        });

        it("closes the session and rejects the pending connect(), throwing nothing, when every host cancel throws", async () => {
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
            const pending = h.sdk.connect();
            expect(timer.pendingDelays).toContain(DEFAULT_SESSION_CONNECT_TIMEOUT_MS);
            expect(() => h.sdk.disconnect()).not.toThrow();
            expect(h.sdk.sessionState).toBe("closed");
            sdkError(await rejection(pending), "connect_failed");
        });

        it("closes the session and announces it", async () => {
            const h = harness();
            await h.sdk.connect();
            h.sdk.disconnect();
            expect(h.sdk.sessionState).toBe("closed");
            expect(h.states()).toEqual(["connecting", "authenticating", "established", "closed"]);
            await flush();
            expect(h.bridge.hasSession).toBe(false);
            expect(h.bridge.factory.last.closedWith).toEqual({ code: 1000, reason: "disconnect" });
        });

        it("is a no-op before any connect(), and idempotent after one", async () => {
            const h = harness();
            expect(() => h.sdk.disconnect()).not.toThrow();
            expect(h.events).toEqual([]);
            await h.sdk.connect();
            h.sdk.disconnect();
            h.sdk.disconnect();
            expect(h.states().filter((state) => state === "closed")).toHaveLength(1);
        });
    });

    describe("events", () => {
        it("forwards an error the session reports without ending it as an ERROR event, with the cause underneath", async () => {
            const h = harness();
            await h.sdk.connect();
            await h.bridge.factory.last.receive("not a frame");
            await flush();
            expect(h.errors()).toHaveLength(1);
            const error = h.errors()[0];
            expect(error?.code).toBe("session_error");
            expect(error?.cause).toBeInstanceOf(SessionError);
            expect((error?.cause as SessionError).kind).toBe("protocol_violation");
            expect(error?.message).toBe(
                `the signer session reported an error (protocol_violation): ${(error?.cause as SessionError).message}`,
            );
            expect(h.sdk.sessionState).toBe("established");
        });

        it("forwards a socket error with its own words, and one without words as it is", async () => {
            const h = harness();
            await h.sdk.connect();
            await h.bridge.factory.last.error(new Error("socket error"));
            await h.bridge.factory.last.error("ECONNRESET");
            await flush();
            expect(h.errors().map((error) => error.message)).toEqual([
                "the signer session reported an error: socket error",
                "the signer session reported an error",
            ]);
            expect(h.errors().map((error) => error.cause)).toEqual([new Error("socket error"), "ECONNRESET"]);
        });

        it("announces the session's state before its error on a lost socket", async () => {
            const h = harness();
            await h.sdk.connect();
            h.bridge.dropConnection();
            await flush();
            const tail = h.events.slice(3).map((event) => (event.type === "SESSION" ? event.state : event.type));
            expect(tail).toEqual(["reconnecting", "ERROR"]);
        });

        it("reaches every listener, a throwing one included, and stops at an unsubscribe", async () => {
            const h = harness();
            const seen: string[] = [];
            const unsubscribe = h.sdk.onEvent((event) => {
                seen.push(`first ${event.type}`);
                throw new Error("listener broke");
            });
            h.sdk.onEvent((event) => seen.push(`second ${event.type}`));
            await h.sdk.connect();
            expect(seen).toEqual(["first SESSION", "second SESSION", "first SESSION", "second SESSION", "first SESSION", "second SESSION"]);
            unsubscribe();
            h.sdk.disconnect();
            expect(seen.slice(6)).toEqual(["second SESSION"]);
        });

        it("delivers an event to the listeners subscribed when it is raised, not to one added on hearing it", async () => {
            const h = harness();
            const seen: SessionState[] = [];
            let added = false;
            h.sdk.onEvent(() => {
                if (added) return;
                added = true;
                h.sdk.onEvent((event) => {
                    if (event.type === "SESSION") seen.push(event.state);
                });
            });
            await h.sdk.connect();
            expect(seen).toEqual(["authenticating", "established"]);
        });
    });

    describe("sessionState", () => {
        it("follows the session", async () => {
            const h = harness();
            expect(h.sdk.sessionState).toBe("idle");
            const pending = h.sdk.connect();
            expect(h.sdk.sessionState).toBe("connecting");
            await pending;
            expect(h.sdk.sessionState).toBe("established");
            h.sdk.disconnect();
            expect(h.sdk.sessionState).toBe("closed");
        });
    });
});
