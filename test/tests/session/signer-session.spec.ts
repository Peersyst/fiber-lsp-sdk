import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import { PROTOCOL_VERSION, decodeInboundFrame, sessionChallengeDigest } from "../../../src/protocol";
import type { ISessionAuthenticator, SessionEvent, SessionOptions, SessionState } from "../../../src/session";
import {
    BridgeError,
    DEFAULT_CONNECT_TIMEOUT_MS,
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    DEFAULT_HEARTBEAT_TIMEOUT_MS,
    MAX_DELAY_MS,
    SessionError,
    SignerSession,
} from "../../../src/session";
import type { DispatchOutcome, PendingChannelRegistration } from "../../../src/signer";
import { WalletIdentity } from "../../../src/signer";
import { DEFAULT_PUB_NONCE, SessionHandlerMock, TimerMock, WebSocketFactoryMock, WebSocketMock } from "../../mocks/session";
import { flush } from "../../utils/flush";
import { loadInteropVectors } from "../../utils/interop-vectors";
import { answerableRefusal, refusal } from "../../utils/refusal";

const vectors = loadInteropVectors();
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const identity = new WalletIdentity(MASTER_SEED);

const URL = "wss://lsp.example/signer";
const CHALLENGE = new Uint8Array(32).fill(0x5c);
const CHALLENGE_FRAME = { type: "challenge", challenge: `0x${bytesToHex(CHALLENGE)}` };
const ESTABLISHED_FRAME = { type: "session_established", protocol_version: PROTOCOL_VERSION, pending_requests: 0 };
const SIGNED_CHALLENGE_FRAME = {
    type: "signed_challenge",
    protocol_version: PROTOCOL_VERSION,
    public_key: `0x${bytesToHex(identity.publicKey)}`,
    signature: `0x${bytesToHex(identity.signChallenge(CHALLENGE))}`,
};
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const PENDING: PendingChannelRegistration = {
    channelIndex: 3,
    localExposureShannons: "62000000000",
    registration: {
        fundingPubkey: pubkeyOf(KEYS.fundingKey),
        tlcBasePubkey: pubkeyOf(KEYS.tlcBaseKey),
        localSettlementKey: KEYS.tlcBaseKey,
    },
};
const REGISTER_CHANNEL_FRAME = {
    type: "register_channel",
    request_id: "1",
    funding_pubkey: `0x${bytesToHex(PENDING.registration.fundingPubkey)}`,
    tlc_base_pubkey: `0x${bytesToHex(PENDING.registration.tlcBasePubkey)}`,
    local_settlement_key: `0x${bytesToHex(PENDING.registration.localSettlementKey)}`,
};
const PUB_NONCE_RESULT = { pub_nonce: `0x${bytesToHex(DEFAULT_PUB_NONCE)}` };
const HEARTBEAT = { heartbeatIntervalMs: 20_000, heartbeatTimeoutMs: 10_000 };

function signRequest(requestId: string) {
    return {
        type: "sign_request",
        request_id: requestId,
        channel_id: CHANNEL_ID,
        method: "get_commitment_point",
        params: { commitment_number: "0x5" },
        state_version: "0x7",
    };
}

function signResponse(requestId: string) {
    return { type: "sign_response", request_id: requestId, result: PUB_NONCE_RESULT };
}

function registered(requestId: string, channelId = CHANNEL_ID) {
    return { type: "channel_registered", request_id: requestId, channel_id: channelId };
}

function harness(overrides: Partial<SessionOptions> = {}) {
    const factory = new WebSocketFactoryMock();
    const timer = new TimerMock();
    const handler = new SessionHandlerMock();
    const events: SessionEvent[] = [];
    const session = new SignerSession({
        url: URL,
        createWebSocket: factory.create,
        timer,
        authenticator: identity,
        handler,
        random: () => 1,
        heartbeatIntervalMs: 0,
        ...overrides,
    });
    session.onEvent((event) => events.push(event));
    const states = (): SessionState[] => events.flatMap((event) => (event.type === "state" ? [event.state] : []));
    const errors = (): unknown[] => events.flatMap((event) => (event.type === "error" ? [event.cause] : []));
    return { session, factory, sockets: factory.sockets, timer, handler, events, states, errors };
}

type Harness = ReturnType<typeof harness>;

async function establish(h: Harness): Promise<WebSocketMock> {
    const connected = h.session.connect();
    const socket = h.factory.last;
    await socket.receive(CHALLENGE_FRAME);
    await socket.receive(ESTABLISHED_FRAME);
    await connected;
    return socket;
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
    try {
        await promise;
    } catch (error) {
        return error;
    }
    throw new Error("did not reject");
}

function sessionError(error: unknown, kind: SessionError["kind"]): SessionError {
    expect(error).toBeInstanceOf(SessionError);
    expect((error as SessionError).kind).toBe(kind);
    return error as SessionError;
}

function holdAnswers(handler: SessionHandlerMock): ((outcome?: DispatchOutcome) => void)[] {
    const releases: ((outcome?: DispatchOutcome) => void)[] = [];
    const answered: DispatchOutcome = { kind: "result", result: { kind: "pub_nonce", pubNonce: DEFAULT_PUB_NONCE } };
    handler.respond = () => new Promise((resolve) => releases.push((outcome = answered) => resolve(outcome)));
    return releases;
}

describe("SignerSession", () => {
    describe("options", () => {
        it.each([
            ["connectTimeoutMs", 0],
            ["connectTimeoutMs", -1],
            ["connectTimeoutMs", 1.5],
            ["connectTimeoutMs", NaN],
            ["connectTimeoutMs", MAX_DELAY_MS + 1],
            ["heartbeatIntervalMs", -1],
            ["heartbeatIntervalMs", 0.5],
            ["heartbeatIntervalMs", MAX_DELAY_MS + 1],
            ["heartbeatTimeoutMs", 0],
            ["heartbeatTimeoutMs", -1],
            ["heartbeatTimeoutMs", Infinity],
        ])("refuses %s of %p", (name, value) => {
            expect(() => harness({ [name]: value })).toThrow(RangeError);
        });

        it.each([
            { initialDelayMs: 0 },
            { initialDelayMs: -1 },
            { initialDelayMs: 1.5 },
            { initialDelayMs: MAX_DELAY_MS + 1 },
            { maxDelayMs: 999 },
            { maxDelayMs: 0 },
            { maxDelayMs: MAX_DELAY_MS + 1 },
            { factor: 0.99 },
            { factor: 0 },
            { factor: NaN },
            { factor: Infinity },
            { factor: "2" as unknown as number },
        ])("refuses a reconnect policy of %p", (reconnect) => {
            expect(() => harness({ reconnect })).toThrow(RangeError);
        });

        it.each([
            { heartbeatIntervalMs: 0 },
            { reconnect: { maxDelayMs: 1000 } },
            { reconnect: { factor: 1 } },
            { connectTimeoutMs: MAX_DELAY_MS },
        ])("accepts %p, the edge of what it takes", (options) => {
            expect(() => harness(options)).not.toThrow();
        });

        it("runs with the documented defaults: connect timeout, heartbeat interval and timeout, and the backoff", async () => {
            const h = harness({ heartbeatIntervalMs: undefined, random: undefined });
            const socket = await establish(h);
            expect(h.timer.delays).toEqual([DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_HEARTBEAT_INTERVAL_MS]);
            h.timer.advance(DEFAULT_HEARTBEAT_INTERVAL_MS);
            expect(h.timer.delays.at(-1)).toBe(DEFAULT_HEARTBEAT_TIMEOUT_MS);
            h.timer.advance(DEFAULT_HEARTBEAT_TIMEOUT_MS);
            expect(socket.closedWith).toEqual({ code: 1000, reason: "heartbeat timeout" });
            const backoff = h.timer.delays.at(-1) ?? NaN;
            expect(backoff).toBeGreaterThanOrEqual(0);
            expect(backoff).toBeLessThanOrEqual(1000);
        });

        it("keeps nothing of the host's option object", async () => {
            const options = { reconnect: { initialDelayMs: 1000, factor: 2, maxDelayMs: 30_000 } };
            const h = harness(options);
            options.reconnect.initialDelayMs = 5;
            const socket = await establish(h);
            await socket.closeFromServer();
            expect(h.timer.delays.at(-1)).toBe(1000);
        });
    });

    describe("establishment", () => {
        it("opens a socket at the url, answers the challenge, and is established on the bridge's confirmation", async () => {
            const h = harness();
            const connected = h.session.connect();
            expect(h.factory.last.url).toBe(URL);
            expect(h.states()).toEqual(["connecting"]);
            const socket = h.factory.last;
            await socket.receive(CHALLENGE_FRAME);
            expect(h.states()).toEqual(["connecting", "authenticating"]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            await socket.receive(ESTABLISHED_FRAME);
            await expect(connected).resolves.toBeUndefined();
            expect(h.states()).toEqual(["connecting", "authenticating", "established"]);
            expect(h.session.state).toBe("established");
            expect(h.errors()).toEqual([]);
        });

        it("signs the domain-separated digest of the challenge, which is what the bridge verifies", async () => {
            const h = harness();
            void h.session.connect();
            const socket = h.factory.last;
            await socket.receive(CHALLENGE_FRAME);
            const frame = socket.sent[0] as { public_key: string; signature: string };
            const publicKey = hexToBytes(frame.public_key.slice(2));
            const signature = hexToBytes(frame.signature.slice(2));
            expect(schnorr.verify(signature, sessionChallengeDigest(CHALLENGE), publicKey)).toBe(true);
            expect(schnorr.verify(signature, CHALLENGE, publicKey)).toBe(false);
        });

        it("cancels the connect timeout once established", async () => {
            const h = harness();
            await establish(h);
            expect(h.timer.pending).toBe(0);
        });

        it("reads the pending count and needs nothing from it", async () => {
            const h = harness();
            const connected = h.session.connect();
            const socket = h.factory.last;
            await socket.receive(CHALLENGE_FRAME);
            await socket.receive({ ...ESTABLISHED_FRAME, pending_requests: 7 });
            await expect(connected).resolves.toBeUndefined();
        });

        describe("fails for good, closing the socket and rejecting connect()", () => {
            async function fatal(h: Harness, deliver: (socket: WebSocketMock) => Promise<void>): Promise<SessionError> {
                const connected = h.session.connect();
                const socket = h.factory.last;
                await deliver(socket);
                const error = await rejection(connected);
                expect(h.session.state).toBe("closed");
                expect(h.errors()).toEqual([error]);
                expect(h.timer.pending).toBe(0);
                return error as SessionError;
            }

            it("on a challenge that does not decode", async () => {
                const h = harness();
                const short = { type: "challenge", challenge: `0x${"5c".repeat(31)}` };
                const error = await fatal(h, (socket) => socket.receive(short));
                sessionError(error, "protocol_violation");
                expect(error.message).toBe(refusal(() => decodeInboundFrame(JSON.stringify(short))).message);
                expect(h.factory.last.closedWith).toEqual({ code: 1000, reason: "protocol violation" });
                expect(h.states()).toEqual(["connecting", "closed"]);
            });

            it("on a protocol version other than its own", async () => {
                const h = harness();
                const error = await fatal(h, async (socket) => {
                    await socket.receive(CHALLENGE_FRAME);
                    await socket.receive({ ...ESTABLISHED_FRAME, protocol_version: PROTOCOL_VERSION + 1 });
                });
                sessionError(error, "version_mismatch");
                expect(error.message).toBe(
                    `the bridge speaks protocol version ${PROTOCOL_VERSION + 1}, this device speaks ${PROTOCOL_VERSION}`,
                );
                expect(h.factory.last.closedWith).toEqual({ code: 1000, reason: "protocol version mismatch" });
                expect(h.states()).toEqual(["connecting", "authenticating", "closed"]);
            });

            it.each([
                ["session_established", ESTABLISHED_FRAME],
                ["sign_request", signRequest("a")],
                ["ping", { type: "ping" }],
                ["pong", { type: "pong" }],
                ["channel_registered", registered("1")],
                ["error", { type: "error", request_id: "1", code: "x", message: "y" }],
            ])("on a %s frame before the challenge", async (type, frame) => {
                const h = harness();
                const error = await fatal(h, (socket) => socket.receive(frame));
                sessionError(error, "protocol_violation");
                expect(error.message).toBe(`unexpected ${type} frame while connecting`);
                expect(h.factory.last.closedWith).toEqual({ code: 1000, reason: "protocol violation" });
            });

            it.each([
                ["challenge", CHALLENGE_FRAME],
                ["sign_request", signRequest("a")],
                ["ping", { type: "ping" }],
            ])("on a %s frame in place of the confirmation", async (type, frame) => {
                const h = harness();
                const error = await fatal(h, async (socket) => {
                    await socket.receive(CHALLENGE_FRAME);
                    await socket.receive(frame);
                });
                sessionError(error, "protocol_violation");
                expect(error.message).toBe(`unexpected ${type} frame while authenticating`);
                expect(h.factory.last.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            });

            it("on a sign request that carries an id but does not decode, which is out of order before anything else", async () => {
                const h = harness();
                const malformed = { type: "sign_request", request_id: "a", channel_id: "nope" };
                const error = await fatal(h, async (socket) => {
                    await socket.receive(CHALLENGE_FRAME);
                    await socket.receive(malformed);
                });
                sessionError(error, "protocol_violation");
                expect(error.message).toBe(answerableRefusal(() => decodeInboundFrame(JSON.stringify(malformed))).message);
                expect(h.factory.last.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            });

            it.each([
                ["invalid JSON", "{", "frame must be valid JSON"],
                ["a binary frame", new Uint8Array(3), "frame must be a text frame"],
                ["a frame of an unknown type", { type: "hello" }, refusal(() => decodeInboundFrame('{"type":"hello"}')).message],
            ])("on %s while connecting", async (_, data, message) => {
                const h = harness();
                const error = await fatal(h, (socket) => socket.receive(data));
                sessionError(error, "protocol_violation");
                expect(error.message).toBe(message);
            });

            it("when the authenticator cannot sign the challenge, before anything is sent", async () => {
                const cause = new Error("enclave busy");
                const h = harness({
                    authenticator: {
                        publicKey: identity.publicKey,
                        signChallenge: () => {
                            throw cause;
                        },
                    },
                });
                const error = await fatal(h, (socket) => socket.receive(CHALLENGE_FRAME));
                sessionError(error, "authentication_failed");
                expect(error.message).toBe("the authenticator could not answer the challenge");
                expect(error.cause).toBe(cause);
                expect(h.factory.last.sent).toEqual([]);
                expect(h.factory.last.closedWith).toEqual({ code: 1000, reason: "authentication failed" });
                expect(h.states()).toEqual(["connecting", "closed"]);
            });

            it.each<[string, ISessionAuthenticator, string]>([
                [
                    "a signature that is not 64 bytes",
                    { publicKey: identity.publicKey, signChallenge: () => new Uint8Array(63) },
                    "signature must be 64 bytes, got 63",
                ],
                [
                    "a public key that is not 32 bytes",
                    { publicKey: new Uint8Array(33), signChallenge: (challenge) => identity.signChallenge(challenge) },
                    "publicKey must be 32 bytes, got 33",
                ],
                [
                    "a signature that is no byte array at all",
                    { publicKey: identity.publicKey, signChallenge: () => "0xdead" as unknown as Uint8Array },
                    "signature must be a Uint8Array",
                ],
            ])("when the authenticator answers with %s, which no attempt would improve", async (_, authenticator, detail) => {
                const h = harness({ authenticator });
                const error = await fatal(h, (socket) => socket.receive(CHALLENGE_FRAME));
                sessionError(error, "authentication_failed");
                expect(error.message).toBe("the authenticator could not answer the challenge");
                expect((error.cause as Error).message).toBe(detail);
                expect(h.factory.last.sent).toEqual([]);
                expect(h.factory.last.closedWith).toEqual({ code: 1000, reason: "authentication failed" });
                expect(h.sockets).toHaveLength(1);
            });

            it("when the bridge closes the socket after seeing the signature: the handshake was refused", async () => {
                const h = harness();
                const error = await fatal(h, async (socket) => {
                    await socket.receive(CHALLENGE_FRAME);
                    await socket.closeFromServer(1008, "unknown identity");
                });
                sessionError(error, "handshake_refused");
                expect(error.message).toBe(
                    'the bridge closed the socket during authentication: socket closed (code 1008, reason "unknown identity")',
                );
                expect(h.factory.last.closedWith).toBeUndefined();
                expect(h.sockets).toHaveLength(1);
            });

            it("reports a refusal whose close carried neither code nor reason", async () => {
                const h = harness();
                const error = await fatal(h, async (socket) => {
                    await socket.receive(CHALLENGE_FRAME);
                    await socket.closeFromServer();
                });
                expect(error.message).toBe('the bridge closed the socket during authentication: socket closed (code none, reason "")');
            });

            it("tells the host the state before the cause", async () => {
                const h = harness();
                await fatal(h, (socket) => socket.receive({ type: "hello" }));
                expect(h.events.map((event) => event.type)).toEqual(["state", "state", "error"]);
            });
        });

        describe("fails for now, and reconnects", () => {
            it("when the socket closes before the challenge", async () => {
                const h = harness();
                const connected = h.session.connect();
                const socket = h.factory.last;
                await socket.closeFromServer(1006, "");
                expect(h.states()).toEqual(["connecting", "reconnecting"]);
                expect(h.events.map((event) => event.type)).toEqual(["state", "state", "error"]);
                const error = sessionError(h.errors()[0], "connection_lost");
                expect(error.message).toBe('socket closed (code 1006, reason "")');
                expect(h.timer.delays).toEqual([DEFAULT_CONNECT_TIMEOUT_MS, 1000]);
                h.timer.advance(1000);
                expect(h.sockets).toHaveLength(2);
                await h.factory.last.receive(CHALLENGE_FRAME);
                await h.factory.last.receive(ESTABLISHED_FRAME);
                await expect(connected).resolves.toBeUndefined();
            });

            it("when the socket errors: the error is reported and the close that follows moves the session", async () => {
                const h = harness();
                void h.session.connect();
                const socket = h.factory.last;
                const cause = new Error("ECONNREFUSED");
                await socket.error(cause);
                expect(h.errors()).toEqual([cause]);
                expect(h.session.state).toBe("connecting");
                await socket.closeFromServer(1006);
                expect(h.session.state).toBe("reconnecting");
            });

            it("when nothing arrives within the connect timeout, closing the socket itself", async () => {
                const h = harness();
                const connected = h.session.connect();
                const socket = h.factory.last;
                h.timer.advance(DEFAULT_CONNECT_TIMEOUT_MS - 1);
                expect(h.session.state).toBe("connecting");
                h.timer.advance(1);
                expect(socket.closedWith).toEqual({ code: 1000, reason: "connect timeout" });
                expect(h.session.state).toBe("reconnecting");
                expect(sessionError(h.errors()[0], "connection_lost").message).toBe("connect timeout");
                h.timer.advance(1000);
                await establishOn(h.factory.last);
                await expect(connected).resolves.toBeUndefined();
            });

            it("when the confirmation does not arrive within the connect timeout", async () => {
                const h = harness();
                void h.session.connect();
                const socket = h.factory.last;
                await socket.receive(CHALLENGE_FRAME);
                h.timer.advance(DEFAULT_CONNECT_TIMEOUT_MS);
                expect(socket.closedWith).toEqual({ code: 1000, reason: "connect timeout" });
                expect(h.session.state).toBe("reconnecting");
            });

            it("when the factory throws, trying again after the backoff", async () => {
                const h = harness();
                const failure = new SyntaxError("bad url");
                h.factory.failure = failure;
                const connected = h.session.connect();
                expect(h.states()).toEqual(["connecting", "reconnecting"]);
                expect(h.events.map((event) => event.type)).toEqual(["state", "state", "error"]);
                expect(h.errors()).toEqual([failure]);
                h.factory.failure = undefined;
                h.timer.advance(1000);
                expect(h.sockets).toHaveLength(1);
                await establishOn(h.factory.last);
                await expect(connected).resolves.toBeUndefined();
            });

            it("when the socket refuses the answer to the challenge, which is no refusal of the handshake", async () => {
                const h = harness();
                const connected = h.session.connect();
                const socket = h.factory.last;
                const failure = new Error("EPIPE");
                socket.sendError = failure;
                await socket.receive(CHALLENGE_FRAME);
                expect(h.states()).toEqual(["connecting", "reconnecting"]);
                expect(socket.closedWith).toEqual({ code: 1000, reason: "send failed" });
                expect(h.errors()[0]).toBe(failure);
                expect(sessionError(h.errors()[1], "connection_lost").message).toBe("the socket refused the signed_challenge frame");
                await socket.closeFromServer(1006, "");
                expect(h.session.state).toBe("reconnecting");
                h.timer.advance(1000);
                await establishOn(h.factory.last);
                await expect(connected).resolves.toBeUndefined();
            });
        });
    });

    describe("connect()", () => {
        it("joins an establishment in progress rather than opening a second socket", async () => {
            const h = harness();
            const first = h.session.connect();
            const second = h.session.connect();
            expect(h.sockets).toHaveLength(1);
            await establishOn(h.factory.last);
            await expect(first).resolves.toBeUndefined();
            await expect(second).resolves.toBeUndefined();
        });

        it("resolves at once when established", async () => {
            const h = harness();
            await establish(h);
            await expect(h.session.connect()).resolves.toBeUndefined();
            expect(h.sockets).toHaveLength(1);
        });

        it("cuts a backoff short and opens now", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.closeFromServer();
            expect(h.session.state).toBe("reconnecting");
            const connected = h.session.connect();
            expect(h.sockets).toHaveLength(2);
            expect(h.session.state).toBe("connecting");
            expect(h.timer.pending).toBe(1);
            h.timer.advance(1000);
            expect(h.sockets).toHaveLength(2);
            await establishOn(h.factory.last);
            await expect(connected).resolves.toBeUndefined();
        });

        it("keeps the attempt count when it cuts a backoff short, so the next failure waits where the last one left off", async () => {
            const h = harness();
            await establish(h);
            await h.factory.last.closeFromServer();
            h.timer.advance(1000);
            await h.factory.last.closeFromServer();
            expect(h.timer.delays.at(-1)).toBe(2000);
            void h.session.connect();
            await h.factory.last.closeFromServer();
            expect(h.timer.delays.at(-1)).toBe(4000);
        });

        it("starts over after disconnect(), with the backoff reset", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.closeFromServer();
            h.timer.advance(1000);
            await h.factory.last.closeFromServer();
            expect(h.timer.delays.at(-1)).toBe(2000);
            h.session.disconnect();
            const connected = h.session.connect();
            expect(h.sockets).toHaveLength(3);
            // Failing before establishing, so only connect() can have reset the backoff.
            await h.factory.last.closeFromServer();
            expect(h.timer.delays.at(-1)).toBe(1000);
            h.timer.advance(1000);
            await establishOn(h.factory.last);
            await expect(connected).resolves.toBeUndefined();
        });

        it("starts over after a fatal failure", async () => {
            const h = harness();
            void h.session.connect().catch(() => undefined);
            await h.factory.last.receive({ type: "hello" });
            expect(h.session.state).toBe("closed");
            const connected = h.session.connect();
            expect(h.sockets).toHaveLength(2);
            await establishOn(h.factory.last);
            await expect(connected).resolves.toBeUndefined();
        });

        it("rejects when disconnect() comes first", async () => {
            const h = harness();
            const connected = h.session.connect();
            h.session.disconnect();
            const error = sessionError(await rejection(connected), "disconnected");
            expect(error.message).toBe("disconnect() was called");
            expect(h.factory.last.closedWith).toEqual({ code: 1000, reason: "disconnect" });
        });
    });

    describe("sign requests", () => {
        it("hands each request to the handler and answers it with the result, in delivery order", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.receive(signRequest("a"));
            await socket.receive(signRequest("b"));
            await socket.receive(signRequest("c"));
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a", "b", "c"]);
            expect(h.handler.handled[0]).toEqual({
                requestId: "a",
                channelId: CHANNEL_ID,
                method: "get_commitment_point",
                params: { commitment_number: "0x5" },
                stateVersion: 7,
            });
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, signResponse("a"), signResponse("b"), signResponse("c")]);
            expect(h.errors()).toEqual([]);
        });

        it("never hands the next request over until the current one is answered", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            await socket.receive(signRequest("a"));
            await socket.receive(signRequest("b"));
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a"]);
            releases[0]?.();
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a", "b"]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, signResponse("a")]);
            releases[1]?.();
            await flush();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, signResponse("a"), signResponse("b")]);
        });

        it("answers a refusal with exactly its code and message", async () => {
            const h = harness();
            const socket = await establish(h);
            h.handler.respond = () => ({
                kind: "refusal",
                error: { code: "policy_refusal", message: "slot COMMITMENT:5 served another session" },
            });
            await socket.receive(signRequest("a"));
            await flush();
            expect(socket.sent).toEqual([
                SIGNED_CHALLENGE_FRAME,
                {
                    type: "sign_response",
                    request_id: "a",
                    error: { code: "policy_refusal", message: "slot COMMITMENT:5 served another session" },
                },
            ]);
        });

        it("leaves a fault unanswered, tells the host, and goes on with the next request", async () => {
            const h = harness();
            const socket = await establish(h);
            const cause = Object.assign(new Error("ENOSPC"), { code: "ENOSPC" });
            h.handler.respond = (request) =>
                request.requestId === "a"
                    ? { kind: "fault", cause }
                    : { kind: "result", result: { kind: "pub_nonce", pubNonce: DEFAULT_PUB_NONCE } };
            await socket.receive(signRequest("a"));
            await socket.receive(signRequest("b"));
            await flush();
            expect(h.errors()).toEqual([cause]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, signResponse("b")]);
            expect(h.session.state).toBe("established");
        });

        it("reads a handler that throws as a fault", async () => {
            const h = harness();
            const socket = await establish(h);
            const cause = new Error("bug");
            h.handler.respond = () => {
                throw cause;
            };
            await socket.receive(signRequest("a"));
            await flush();
            expect(h.errors()).toEqual([cause]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
        });

        it("answers an envelope that does not decode as malformed, in its turn", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            const malformed = { type: "sign_request", request_id: "bad", channel_id: "nope" };
            await socket.receive(signRequest("a"));
            await socket.receive(malformed);
            await flush();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            releases[0]?.();
            await flush();
            const error = answerableRefusal(() => decodeInboundFrame(JSON.stringify(malformed)));
            expect(socket.sent).toEqual([
                SIGNED_CHALLENGE_FRAME,
                signResponse("a"),
                { type: "sign_response", request_id: "bad", error: { code: "malformed", message: error.message } },
            ]);
            expect(h.handler.handled).toHaveLength(1);
            expect(h.errors()).toEqual([]);
        });

        it("drops a sign request whose id cannot be read, since nothing could correlate the answer", async () => {
            const h = harness();
            const socket = await establish(h);
            const unreadable = { type: "sign_request", request_id: "", channel_id: CHANNEL_ID };
            await socket.receive(unreadable);
            await flush();
            const error = sessionError(h.errors()[0], "protocol_violation");
            expect(error.message).toBe(refusal(() => decodeInboundFrame(JSON.stringify(unreadable))).message);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            expect(h.handler.handled).toEqual([]);
            expect(h.session.state).toBe("established");
        });

        it("drops the answer when the socket that delivered the request is gone", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            await socket.receive(signRequest("a"));
            await flush();
            await socket.closeFromServer();
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            releases[0]?.();
            await flush();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            expect(next.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            expect(h.errors()).toHaveLength(1);
        });

        it("drops what was queued behind a request when the socket is lost, since the bridge re-delivers", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            await socket.receive(signRequest("a"));
            await socket.receive(signRequest("b"));
            await flush();
            await socket.closeFromServer();
            releases[0]?.();
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a"]);
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            await next.receive(signRequest("b"));
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a", "b"]);
        });

        it("answers a request re-delivered on a new socket on that socket", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.closeFromServer();
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            await next.receive(signRequest("a"));
            await flush();
            expect(next.sent).toEqual([SIGNED_CHALLENGE_FRAME, signResponse("a")]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
        });

        it("reports a socket that refuses the answer", async () => {
            const h = harness();
            const socket = await establish(h);
            const failure = new Error("EPIPE");
            socket.sendError = failure;
            await socket.receive(signRequest("a"));
            await flush();
            expect(h.errors()).toEqual([failure]);
            expect(h.session.state).toBe("established");
        });
    });

    describe("session frames while established", () => {
        it("answers the bridge's ping at once, ahead of a request being processed", async () => {
            const h = harness();
            const socket = await establish(h);
            holdAnswers(h.handler);
            await socket.receive(signRequest("a"));
            await socket.receive({ type: "ping" });
            await flush();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, { type: "pong" }]);
        });

        it("takes a pong as a sign of life and nothing else", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.receive({ type: "pong" });
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            expect(h.errors()).toEqual([]);
        });

        it.each([
            ["challenge", CHALLENGE_FRAME],
            ["session_established", ESTABLISHED_FRAME],
        ])("drops a %s frame, reporting it, and stays established", async (type, frame) => {
            const h = harness();
            const socket = await establish(h);
            await socket.receive(frame);
            const error = sessionError(h.errors()[0], "protocol_violation");
            expect(error.message).toBe(`unexpected ${type} frame while established`);
            expect(h.session.state).toBe("established");
            expect(socket.closedWith).toBeUndefined();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
        });

        it.each([
            ["invalid JSON", "{", "frame must be valid JSON"],
            ["a binary frame", new Uint8Array(3), "frame must be a text frame"],
            ["a frame of an unknown type", { type: "hello" }, refusal(() => decodeInboundFrame('{"type":"hello"}')).message],
        ])("drops %s, reporting it, and stays established", async (_, data, message) => {
            const h = harness();
            const socket = await establish(h);
            await socket.receive(data);
            const error = sessionError(h.errors()[0], "protocol_violation");
            expect(error.message).toBe(message);
            expect(h.session.state).toBe("established");
            expect(socket.closedWith).toBeUndefined();
        });
    });

    describe("heartbeat", () => {
        it("pings after the interval of inbound silence and gives the socket up after the timeout", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            h.timer.advance(19_999);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            h.timer.advance(1);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, { type: "ping" }]);
            h.timer.advance(9_999);
            expect(socket.closedWith).toBeUndefined();
            h.timer.advance(1);
            expect(socket.closedWith).toEqual({ code: 1000, reason: "heartbeat timeout" });
            expect(h.session.state).toBe("reconnecting");
            expect(sessionError(h.errors()[0], "connection_lost").message).toBe("heartbeat timeout");
        });

        it("gives the socket up at once when the ping cannot be sent, rather than waiting out the timeout", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            const failure = new Error("EPIPE");
            socket.sendError = failure;
            h.timer.advance(20_000);
            expect(socket.closedWith).toEqual({ code: 1000, reason: "send failed" });
            expect(h.errors()[0]).toBe(failure);
            expect(sessionError(h.errors()[1], "connection_lost").message).toBe("the socket refused the ping frame");
            expect(h.session.state).toBe("reconnecting");
            expect(h.timer.delays.at(-1)).toBe(1000);
        });

        it("is reset by any inbound frame", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            h.timer.advance(15_000);
            await socket.receive(signRequest("a"));
            await flush();
            h.timer.advance(19_999);
            expect(socket.sent.filter((frame) => (frame as { type: string }).type === "ping")).toHaveLength(0);
            h.timer.advance(1);
            expect(socket.sent.filter((frame) => (frame as { type: string }).type === "ping")).toHaveLength(1);
        });

        it("is reset by a frame that does not decode, which is a bridge alive all the same", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            h.timer.advance(15_000);
            await socket.receive("{");
            expect(h.errors()).toHaveLength(1);
            h.timer.advance(19_999);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            h.timer.advance(1);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, { type: "ping" }]);
        });

        it("is not reset by what the device sends", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            h.timer.advance(10_000);
            void h.session.registerChannel(PENDING).catch(() => undefined);
            h.timer.advance(10_000);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, REGISTER_CHANNEL_FRAME, { type: "ping" }]);
        });

        it("takes the pong as the answer and keeps the socket", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            h.timer.advance(20_000);
            await socket.receive({ type: "pong" });
            h.timer.advance(10_000);
            expect(socket.closedWith).toBeUndefined();
            h.timer.advance(10_000);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, { type: "ping" }, { type: "ping" }]);
        });

        it("is off at an interval of zero", async () => {
            const h = harness({ heartbeatIntervalMs: 0 });
            await establish(h);
            expect(h.timer.pending).toBe(0);
            h.timer.advance(1_000_000);
            expect(h.session.state).toBe("established");
        });

        it("runs on the new socket after a reconnect, never on the old one", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            await socket.closeFromServer();
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            h.timer.advance(20_000);
            expect(next.sent).toEqual([SIGNED_CHALLENGE_FRAME, { type: "ping" }]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
        });

        it("stops with the session", async () => {
            const h = harness(HEARTBEAT);
            await establish(h);
            h.session.disconnect();
            expect(h.timer.pending).toBe(0);
        });
    });

    describe("reconnection", () => {
        async function fail(h: Harness, times: number): Promise<void> {
            for (let attempt = 0; attempt < times; attempt++) {
                await h.factory.last.closeFromServer();
                h.timer.advance(h.timer.delays.at(-1) ?? 0);
            }
        }

        function backoffs(h: Harness): number[] {
            return h.timer.delays.filter((delay) => delay !== DEFAULT_CONNECT_TIMEOUT_MS);
        }

        it("waits an exponential, capped delay before each attempt", async () => {
            const h = harness();
            await establish(h);
            await fail(h, 7);
            expect(backoffs(h)).toEqual([1000, 2000, 4000, 8000, 16_000, 30_000, 30_000]);
            expect(h.sockets).toHaveLength(8);
        });

        it("jitters every delay by the random draw", async () => {
            const h = harness({ random: () => 0.5 });
            await establish(h);
            await fail(h, 3);
            expect(backoffs(h)).toEqual([500, 1000, 2000]);
        });

        it("takes the policy from the options", async () => {
            const h = harness({ reconnect: { initialDelayMs: 100, factor: 3, maxDelayMs: 1000 } });
            await establish(h);
            await fail(h, 4);
            expect(backoffs(h)).toEqual([100, 300, 900, 1000]);
        });

        it("starts the backoff over once a session is established", async () => {
            const h = harness();
            await establish(h);
            await fail(h, 2);
            await establishOn(h.factory.last);
            await fail(h, 1);
            expect(backoffs(h)).toEqual([1000, 2000, 1000]);
        });

        it("does nothing but wait during the backoff", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.closeFromServer();
            expect(h.session.state).toBe("reconnecting");
            expect(h.timer.pending).toBe(1);
            h.timer.advance(999);
            expect(h.sockets).toHaveLength(1);
            h.timer.advance(1);
            expect(h.sockets).toHaveLength(2);
            expect(h.states()).toEqual(["connecting", "authenticating", "established", "reconnecting", "connecting"]);
        });

        it("rejects the registrations that were waiting on the lost socket", async () => {
            const h = harness();
            const socket = await establish(h);
            const registration = h.session.registerChannel(PENDING);
            await socket.closeFromServer(1006, "gone");
            const error = sessionError(await rejection(registration), "connection_lost");
            expect(error.message).toBe('socket closed (code 1006, reason "gone")');
        });

        it("keeps reconnecting while the bridge keeps closing, until disconnect()", async () => {
            const h = harness();
            await establish(h);
            await fail(h, 20);
            expect(h.session.state).toBe("connecting");
            h.session.disconnect();
            expect(h.session.state).toBe("closed");
            expect(h.timer.pending).toBe(0);
        });
    });

    describe("disconnect()", () => {
        it("closes the socket, cancels every timer, and tells the host without an error", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            h.session.disconnect();
            expect(socket.closedWith).toEqual({ code: 1000, reason: "disconnect" });
            expect(h.states()).toEqual(["connecting", "authenticating", "established", "closed"]);
            expect(h.errors()).toEqual([]);
            expect(h.timer.pending).toBe(0);
        });

        it.each(["connecting", "authenticating"] as const)("closes the socket while %s", async (state) => {
            const h = harness();
            const connected = h.session.connect();
            const socket = h.factory.last;
            if (state === "authenticating") await socket.receive(CHALLENGE_FRAME);
            expect(h.session.state).toBe(state);
            h.session.disconnect();
            expect(socket.closedWith).toEqual({ code: 1000, reason: "disconnect" });
            sessionError(await rejection(connected), "disconnected");
        });

        it("cancels a pending reconnect", async () => {
            const h = harness();
            const socket = await establish(h);
            await socket.closeFromServer();
            h.session.disconnect();
            expect(h.timer.pending).toBe(0);
            h.timer.advance(60_000);
            expect(h.sockets).toHaveLength(1);
            expect(h.session.state).toBe("closed");
        });

        it("does nothing when idle or already closed", async () => {
            const h = harness();
            h.session.disconnect();
            expect(h.session.state).toBe("idle");
            expect(h.events).toEqual([]);
            await establish(h);
            h.session.disconnect();
            h.session.disconnect();
            expect(h.states()).toEqual(["connecting", "authenticating", "established", "closed"]);
        });

        it("ignores whatever the old socket still delivers", async () => {
            const h = harness();
            const socket = await establish(h);
            h.session.disconnect();
            const before = h.events.length;
            await socket.receive(signRequest("a"));
            await socket.receive(CHALLENGE_FRAME);
            await socket.error(new Error("late"));
            await socket.closeFromServer(1006);
            await flush();
            expect(h.events).toHaveLength(before);
            expect(h.handler.handled).toEqual([]);
            expect(h.session.state).toBe("closed");
        });

        it("drops the answer of a request still being processed", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            await socket.receive(signRequest("a"));
            await flush();
            h.session.disconnect();
            releases[0]?.();
            await flush();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            expect(h.errors()).toEqual([]);
        });

        it("rejects the registrations still waiting", async () => {
            const h = harness();
            await establish(h);
            const registration = h.session.registerChannel(PENDING);
            h.session.disconnect();
            sessionError(await rejection(registration), "disconnected");
        });

        it("reports a socket whose close throws, and closes the session all the same", async () => {
            const h = harness();
            const socket = await establish(h);
            const failure = new Error("already closing");
            socket.closeError = failure;
            h.session.disconnect();
            expect(h.errors()).toEqual([failure]);
            expect(h.session.state).toBe("closed");
            expect(h.timer.pending).toBe(0);
        });
    });

    describe("registerChannel()", () => {
        it("sends the registration and resolves with the name the node gave, once the handler has filed it", async () => {
            const h = harness();
            const socket = await establish(h);
            const registration = h.session.registerChannel(PENDING);
            await flush();
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, REGISTER_CHANNEL_FRAME]);
            expect(h.handler.registered).toEqual([]);
            await socket.receive(registered("1"));
            await expect(registration).resolves.toBe(CHANNEL_ID);
            expect(h.handler.registered).toHaveLength(1);
            expect(h.handler.registered[0]?.channelId).toBe(CHANNEL_ID);
            expect(h.handler.registered[0]?.pending).toBe(PENDING);
        });

        it("files the channel in its turn, ahead of the sign request that follows the acknowledgement", async () => {
            const h = harness();
            const socket = await establish(h);
            let release: () => void = () => undefined;
            h.handler.file = () => new Promise<void>((resolve) => (release = resolve));
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(registered("1"));
            await socket.receive(signRequest("a"));
            await flush();
            expect(h.handler.handled).toEqual([]);
            release();
            await registration;
            await flush();
            expect(h.handler.registered).toHaveLength(1);
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a"]);
        });

        it("gives every registration its own id, never reused across sockets", async () => {
            const h = harness();
            const socket = await establish(h);
            void h.session.registerChannel(PENDING).catch(() => undefined);
            void h.session.registerChannel(PENDING).catch(() => undefined);
            await socket.closeFromServer();
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            void h.session.registerChannel(PENDING).catch(() => undefined);
            const ids = (mock: WebSocketMock) =>
                mock.sent.flatMap((frame) =>
                    (frame as { request_id?: string }).request_id ? [(frame as { request_id: string }).request_id] : [],
                );
            expect(ids(socket)).toEqual(["1", "2"]);
            expect(ids(next)).toEqual(["3"]);
        });

        it("rejects with the bridge's own code and message on an error frame", async () => {
            const h = harness();
            const socket = await establish(h);
            const registration = h.session.registerChannel(PENDING);
            await socket.receive({ type: "error", request_id: "1", code: "duplicate_keys", message: "a channel with these keys exists" });
            const error = await rejection(registration);
            expect(error).toBeInstanceOf(BridgeError);
            expect(error).toMatchObject({ code: "duplicate_keys", message: "a channel with these keys exists" });
            expect(h.handler.registered).toEqual([]);
            expect(h.errors()).toEqual([]);
        });

        it("answers each registration once: a second frame for the same id matches nothing", async () => {
            const h = harness();
            const socket = await establish(h);
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(registered("1"));
            await registration;
            await socket.receive(registered("1"));
            await flush();
            expect(sessionError(h.errors()[0], "protocol_violation").message).toBe("channel_registered frame for an unknown request id 1");
            expect(h.handler.registered).toHaveLength(1);
        });

        it.each([
            ["channel_registered", registered("9")],
            ["error", { type: "error", request_id: "9", code: "x", message: "y" }],
        ])("reports a %s frame that correlates with nothing, and stays established", async (type, frame) => {
            const h = harness();
            const socket = await establish(h);
            await socket.receive(frame);
            await flush();
            expect(sessionError(h.errors()[0], "protocol_violation").message).toBe(`${type} frame for an unknown request id 9`);
            expect(h.session.state).toBe("established");
        });

        it("rejects when there is no established session", async () => {
            const h = harness();
            const error = sessionError(await rejection(h.session.registerChannel(PENDING)), "not_connected");
            expect(error.message).toBe("registerChannel needs an established session, the session is idle");
            void h.session.connect();
            sessionError(await rejection(h.session.registerChannel(PENDING)), "not_connected");
            const socket = h.factory.last;
            await socket.receive(CHALLENGE_FRAME);
            sessionError(await rejection(h.session.registerChannel(PENDING)), "not_connected");
            await socket.receive(ESTABLISHED_FRAME);
            await socket.closeFromServer();
            expect(sessionError(await rejection(h.session.registerChannel(PENDING)), "not_connected").message).toBe(
                "registerChannel needs an established session, the session is reconnecting",
            );
            h.session.disconnect();
            sessionError(await rejection(h.session.registerChannel(PENDING)), "not_connected");
            expect(h.factory.last.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
        });

        it("rejects with the handler's failure when the channel cannot be filed, and goes on", async () => {
            const h = harness();
            const socket = await establish(h);
            const cause = new Error("storage is read only");
            h.handler.file = () => {
                throw cause;
            };
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(registered("1"));
            expect(await rejection(registration)).toBe(cause);
            expect(h.session.state).toBe("established");
            h.handler.file = () => undefined;
            const again = h.session.registerChannel(PENDING);
            await socket.receive(registered("2"));
            await expect(again).resolves.toBe(CHANNEL_ID);
        });

        it("rejects at once when the socket refuses the frame", async () => {
            const h = harness();
            const socket = await establish(h);
            const failure = new Error("EPIPE");
            socket.sendError = failure;
            const error = sessionError(await rejection(h.session.registerChannel(PENDING)), "connection_lost");
            expect(error.message).toBe("the socket refused the register_channel frame");
            expect(h.errors()).toEqual([failure]);
            socket.sendError = undefined;
            await socket.receive(registered("1"));
            await flush();
            sessionError(h.errors()[1], "protocol_violation");
        });

        it("lets a registration being filed settle by the handler even if the session closes meanwhile", async () => {
            const h = harness();
            const socket = await establish(h);
            let release: () => void = () => undefined;
            h.handler.file = () => new Promise<void>((resolve) => (release = resolve));
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(registered("1"));
            await flush();
            h.session.disconnect();
            release();
            await expect(registration).resolves.toBe(CHANNEL_ID);
        });

        it.each<[string, (h: Harness, socket: WebSocketMock) => unknown]>([
            ["the bridge closes the socket", (_, socket) => socket.closeFromServer(1006, "gone")],
            ["disconnect() is called", (h) => h.session.disconnect()],
        ])("files an acknowledgement still queued when %s, in its turn, since nothing re-delivers it", async (_, end) => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(signRequest("a"));
            await socket.receive(registered("1"));
            await socket.receive(signRequest("b"));
            await flush();
            await end(h, socket);
            expect(h.handler.registered).toEqual([]);
            releases[0]?.();
            await expect(registration).resolves.toBe(CHANNEL_ID);
            expect(h.handler.registered).toEqual([{ channelId: CHANNEL_ID, pending: PENDING }]);
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a"]);
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME, REGISTER_CHANNEL_FRAME]);
        });

        it("rejects with the bridge's refusal still queued when the socket is lost, not with the loss", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(signRequest("a"));
            await socket.receive({ type: "error", request_id: "1", code: "duplicate_keys", message: "a channel with these keys exists" });
            await flush();
            await socket.closeFromServer();
            releases[0]?.();
            const error = await rejection(registration);
            expect(error).toBeInstanceOf(BridgeError);
            expect(error).toMatchObject({ code: "duplicate_keys", message: "a channel with these keys exists" });
            expect(h.errors()).toHaveLength(1);
            sessionError(h.errors()[0], "connection_lost");
        });

        it("files an acknowledgement kept from a lost socket ahead of what the next socket delivers", async () => {
            const h = harness();
            const socket = await establish(h);
            const releases = holdAnswers(h.handler);
            const registration = h.session.registerChannel(PENDING);
            await socket.receive(signRequest("a"));
            await socket.receive(registered("1"));
            await flush();
            await socket.closeFromServer();
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            const handledWhenFiled: string[][] = [];
            h.handler.file = () => {
                handledWhenFiled.push(h.handler.handled.map((request) => request.requestId));
            };
            await next.receive(signRequest("b"));
            await flush();
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a"]);
            releases[0]?.();
            await registration;
            await flush();
            expect(handledWhenFiled).toEqual([["a"]]);
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a", "b"]);
            releases[1]?.();
            await flush();
            expect(next.sent).toEqual([SIGNED_CHALLENGE_FRAME, signResponse("b")]);
        });

        it("reports an acknowledgement that matches nothing as it arrives, not in its turn", async () => {
            const h = harness();
            const socket = await establish(h);
            holdAnswers(h.handler);
            await socket.receive(signRequest("a"));
            await socket.receive(registered("9"));
            await flush();
            expect(sessionError(h.errors()[0], "protocol_violation").message).toBe("channel_registered frame for an unknown request id 9");
            expect(h.handler.handled.map((request) => request.requestId)).toEqual(["a"]);
        });
    });

    describe("robustness", () => {
        it("ignores an event a runtime had already dequeued when the session let go of the socket", async () => {
            const h = harness();
            const socket = await establish(h);
            const { onmessage, onclose, onerror } = socket;
            h.session.disconnect();
            const before = h.events.length;
            onmessage?.({ data: JSON.stringify(signRequest("a")) });
            onerror?.(new Error("late"));
            onclose?.({ code: 1006, reason: "" });
            await flush();
            expect(h.events).toHaveLength(before);
            expect(h.handler.handled).toEqual([]);
            expect(h.session.state).toBe("closed");
        });

        it("survives a host timer whose cancel does nothing: a stale heartbeat never touches the next socket", async () => {
            const h = harness(HEARTBEAT);
            h.timer.ignoreCancel = true;
            const socket = await establish(h);
            await socket.closeFromServer();
            h.timer.advance(1000);
            const next = h.factory.last;
            await establishOn(next);
            h.timer.advance(19_000);
            expect(next.closedWith).toBeUndefined();
            expect(next.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            h.timer.advance(1_000);
            expect(next.sent).toEqual([SIGNED_CHALLENGE_FRAME, { type: "ping" }]);
            h.timer.advance(9_999);
            expect(next.closedWith).toBeUndefined();
            expect(h.session.state).toBe("established");
        });

        it("survives a stale connect timeout under such a timer", async () => {
            const h = harness();
            h.timer.ignoreCancel = true;
            const socket = await establish(h);
            h.timer.advance(DEFAULT_CONNECT_TIMEOUT_MS);
            expect(socket.closedWith).toBeUndefined();
            expect(h.session.state).toBe("established");
        });
    });

    describe("reentrancy from listeners", () => {
        function on(h: Harness, state: SessionState, action: () => void): void {
            let done = false;
            h.session.onEvent((event) => {
                if (done || event.type !== "state" || event.state !== state) return;
                done = true;
                action();
            });
        }

        it("connect() from the closed event of a fatal failure starts a new session that the failure does not reject", async () => {
            const h = harness();
            let restarted: Promise<void> | undefined;
            on(h, "closed", () => {
                restarted = h.session.connect();
            });
            const connected = h.session.connect();
            await h.factory.last.receive({ type: "hello" });
            sessionError(await rejection(connected), "protocol_violation");
            expect(h.sockets).toHaveLength(2);
            await establishOn(h.factory.last);
            await expect(restarted).resolves.toBeUndefined();
        });

        it("connect() from the closed event of disconnect() starts a new session that disconnect() does not reject", async () => {
            const h = harness();
            let restarted: Promise<void> | undefined;
            on(h, "closed", () => {
                restarted = h.session.connect();
            });
            await establish(h);
            h.session.disconnect();
            expect(h.sockets).toHaveLength(2);
            await establishOn(h.factory.last);
            await expect(restarted).resolves.toBeUndefined();
        });

        it("disconnect() from the reconnecting event cancels the backoff it was told about", async () => {
            const h = harness();
            on(h, "reconnecting", () => h.session.disconnect());
            const socket = await establish(h);
            await socket.closeFromServer();
            expect(h.session.state).toBe("closed");
            expect(h.timer.pending).toBe(0);
            h.timer.advance(60_000);
            expect(h.sockets).toHaveLength(1);
        });

        it("connect() from the reconnecting event opens at once, and only once", async () => {
            const h = harness();
            on(h, "reconnecting", () => void h.session.connect());
            const socket = await establish(h);
            await socket.closeFromServer();
            expect(h.session.state).toBe("connecting");
            expect(h.sockets).toHaveLength(2);
            await establishOn(h.factory.last);
            h.timer.advance(60_000);
            expect(h.sockets).toHaveLength(2);
        });

        it("disconnect() from the connecting event opens no socket", async () => {
            const h = harness();
            on(h, "connecting", () => h.session.disconnect());
            const connected = h.session.connect();
            sessionError(await rejection(connected), "disconnected");
            expect(h.sockets).toHaveLength(0);
            expect(h.session.state).toBe("closed");
        });

        it("connect() from the connecting event of a session it just ended opens the new session's socket, and only it", async () => {
            const h = harness();
            let restarted: Promise<void> | undefined;
            on(h, "connecting", () => {
                h.session.disconnect();
                restarted = h.session.connect();
            });
            const connected = h.session.connect();
            sessionError(await rejection(connected), "disconnected");
            expect(h.sockets).toHaveLength(1);
            await establishOn(h.factory.last);
            await expect(restarted).resolves.toBeUndefined();
        });

        it("disconnect() from the authenticating event closes the socket the signature went out on", async () => {
            const h = harness();
            on(h, "authenticating", () => h.session.disconnect());
            const connected = h.session.connect();
            const socket = h.factory.last;
            await socket.receive(CHALLENGE_FRAME);
            sessionError(await rejection(connected), "disconnected");
            expect(socket.sent).toEqual([SIGNED_CHALLENGE_FRAME]);
            expect(socket.closedWith).toEqual({ code: 1000, reason: "disconnect" });
        });

        it("disconnect() from the established event leaves no heartbeat behind", async () => {
            const h = harness(HEARTBEAT);
            on(h, "established", () => h.session.disconnect());
            const connected = h.session.connect();
            await establishOn(h.factory.last);
            sessionError(await rejection(connected), "disconnected");
            expect(h.timer.pending).toBe(0);
            expect(h.session.state).toBe("closed");
        });

        it("connect() from the established event of a session it just ended is answered by the new session, not that one", async () => {
            const h = harness();
            let outcome: unknown;
            on(h, "established", () => {
                h.session.disconnect();
                void h.session.connect().then(
                    () => (outcome = "connected"),
                    (error: unknown) => (outcome = error),
                );
            });
            const connected = h.session.connect();
            await establishOn(h.factory.last);
            sessionError(await rejection(connected), "disconnected");
            expect(h.session.state).toBe("connecting");
            await flush();
            expect(outcome).toBeUndefined();
            await establishOn(h.factory.last);
            await flush();
            expect(outcome).toBe("connected");
        });

        it("disconnect() from the error of a close that throws leaves the session closed, not reconnecting", async () => {
            const h = harness(HEARTBEAT);
            const socket = await establish(h);
            socket.closeError = new Error("already closing");
            h.session.onEvent((event) => {
                if (event.type === "error") h.session.disconnect();
            });
            h.timer.advance(20_000);
            h.timer.advance(10_000);
            expect(h.states()).toEqual(["connecting", "authenticating", "established", "closed"]);
            expect(h.timer.pending).toBe(0);
            h.timer.advance(60_000);
            expect(h.sockets).toHaveLength(1);
        });

        it("connect() from the error of a close that throws reports no session the disconnect is ending", async () => {
            const h = harness();
            const socket = await establish(h);
            socket.closeError = new Error("already closing");
            const outcomes: unknown[] = [];
            h.session.onEvent((event) => {
                if (event.type !== "error") return;
                void h.session.connect().then(
                    () => outcomes.push("connected"),
                    (error: unknown) => outcomes.push(error),
                );
            });
            h.session.disconnect();
            await flush();
            expect(outcomes).toHaveLength(1);
            sessionError(outcomes[0], "disconnected");
            expect(h.sockets).toHaveLength(1);
        });

        it("disconnect() from the error event of a lost socket stops the reconnect", async () => {
            const h = harness();
            h.session.onEvent((event) => {
                if (event.type === "error") h.session.disconnect();
            });
            const socket = await establish(h);
            await socket.closeFromServer();
            expect(h.session.state).toBe("closed");
            expect(h.timer.pending).toBe(0);
        });
    });

    describe("events", () => {
        it("survives a listener that throws, and still reaches the others", async () => {
            const h = harness();
            const seen: SessionState[] = [];
            h.session.onEvent(() => {
                throw new Error("listener bug");
            });
            h.session.onEvent((event) => {
                if (event.type === "state") seen.push(event.state);
            });
            await establish(h);
            expect(seen).toEqual(["connecting", "authenticating", "established"]);
            expect(h.session.state).toBe("established");
        });

        it("stops at unsubscribe", async () => {
            const h = harness();
            const seen: SessionEvent[] = [];
            const unsubscribe = h.session.onEvent((event) => seen.push(event));
            void h.session.connect();
            unsubscribe();
            await establishOn(h.factory.last);
            expect(seen).toEqual([{ type: "state", state: "connecting" }]);
        });

        it("leaves a listener another one adds out of the event being raised, and takes it from the next", async () => {
            const h = harness();
            const late: SessionEvent[] = [];
            h.session.onEvent((event) => {
                if (event.type === "state" && event.state === "connecting") h.session.onEvent((next) => late.push(next));
            });
            void h.session.connect();
            expect(late).toEqual([]);
            await establishOn(h.factory.last);
            expect(late).toEqual([
                { type: "state", state: "authenticating" },
                { type: "state", state: "established" },
            ]);
        });

        it("lets a listener unsubscribe itself while being called", async () => {
            const h = harness();
            const seen: SessionEvent[] = [];
            const unsubscribe = h.session.onEvent((event) => {
                seen.push(event);
                unsubscribe();
            });
            await establish(h);
            expect(seen).toEqual([{ type: "state", state: "connecting" }]);
            expect(h.states()).toHaveLength(3);
        });

        it("exposes the state the last event announced", async () => {
            const h = harness();
            expect(h.session.state).toBe("idle");
            const socket = await establish(h);
            expect(h.session.state).toBe("established");
            await socket.closeFromServer();
            expect(h.session.state).toBe("reconnecting");
            expect(h.states().at(-1)).toBe("reconnecting");
        });

        it("passes a socket error through as the cause", async () => {
            const h = harness();
            const socket = await establish(h);
            const cause = { type: "error", message: "network changed" };
            await socket.error(cause);
            expect(h.errors()[0]).toBe(cause);
            expect(h.session.state).toBe("established");
        });
    });
});

async function establishOn(socket: WebSocketMock): Promise<void> {
    await socket.receive(CHALLENGE_FRAME);
    await socket.receive(ESTABLISHED_FRAME);
}
