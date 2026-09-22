import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { keyAggExport, keyAggregate } from "@scure/btc-signer/musig2.js";
import { compareBytes } from "../../../src/common";
import { deriveChannelKeys, deriveChannelSeed, deriveWalletIdentityKey, pubkeyOf } from "../../../src/derivation";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import type { ISignerStorage } from "../../../src/policy";
import { ANNOUNCEMENT_SLOT_NUMBER, CHANNEL_POLICY_RECORD_VERSION, PolicyEngine, SignerStore } from "../../../src/policy";
import type { SignMethodParamsWire, SignSessionWire } from "../../../src/protocol";
import { PROTOCOL_VERSION, SIGNER_METHODS } from "../../../src/protocol";
import type { ISessionAuthenticator, ISessionHandler, SessionEvent, SessionOptions } from "../../../src/session";
import { BridgeError, SignerSession } from "../../../src/session";
import type { DispatchOutcome } from "../../../src/signer";
import { SignerDispatch, WalletIdentity, getBasePublicKeys, getChannelCommitmentPoint, getPublicNonce } from "../../../src/signer";
import { InMemorySignerStorage } from "../../mocks/policy";
import { TimerMock } from "../../mocks/session";
import { flush } from "../../utils/flush";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { SHUTDOWN_NONCE_NUMBER, revocationNonceNumber } from "../../utils/nonce-numbers";
import { rejection } from "../../utils/rejection";
import { sessionError } from "../../utils/session-error";
import type { BridgeSignOutcome } from "../../utils/signer-bridge";
import { InMemorySignerBridge } from "../../utils/signer-bridge";
import { standInAggregatedNonce } from "../../utils/stand-in-nonce";
import {
    toCommitmentNumberParamsWire,
    toPartialSignChannelAnnouncementParamsWire,
    toPartialSignClosingTxParamsWire,
    toPartialSignCommitmentTxParamsWire,
    toPartialSignRevocationParamsWire,
    toSignSessionWire,
} from "../../utils/wire-requests";

const vectors = loadInteropVectors();
const digest = vectors.digest;
const REMOTE = digest.remote;
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const OTHER_SEED = new Uint8Array(32).fill(0x42);
const CHANNEL_INDEX = vectors.sdk_scheme.channel.channel_index;
const OTHER_CHANNEL_INDEX = CHANNEL_INDEX + 1;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const OTHER_KEYS = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, OTHER_CHANNEL_INDEX));
const PEER_KEYS = deriveChannelKeys(hexToBytes(REMOTE.seed));
const LOCAL_FUNDING_PUBKEY = pubkeyOf(KEYS.fundingKey);
const PEER_FUNDING_PUBKEY = pubkeyOf(PEER_KEYS.fundingKey);

// The digests bind the vectors' channel keys, so only the channel at the vectors' index can sign them.
const OPEN = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
const SEND = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote");
const SEND_SIDE_REVOCATION = caseOf(digest.revocation_cases, "ckb, send side");
const CLOSE = caseOf(digest.shutdown_cases, "ckb");
const ANNOUNCEMENT = caseOf(digest.announcement_cases, "ckb");

const OPENING_EXPOSURE = OPEN.settlement_local;
const SEND_DECREASE = (BigInt(OPEN.settlement_local) - BigInt(SEND.settlement_local)).toString();
const REVOCATION_NONCE_NUMBER = revocationNonceNumber(SEND_SIDE_REVOCATION);

const URL = "wss://lsp.example/signer";
const RECONNECT_DELAY_MS = 1000;
const HEARTBEAT = { heartbeatIntervalMs: 20_000, heartbeatTimeoutMs: 10_000 };

// The sign-once registry stores a commitment to the session the bridge built, which the flows never see.
const SESSION_COMMITMENT: unknown = expect.stringMatching(/^[0-9a-f]{64}$/);

const STAND_IN_NONCE = standInAggregatedNonce(0x01);

type Device = {
    session: SignerSession;
    dispatch: SignerDispatch;
    policy: PolicyEngine;
    store: SignerStore;
    timer: TimerMock;
    outcomes: Promise<DispatchOutcome>[];
    events: SessionEvent[];
    errors: () => unknown[];
};

type DeviceOptions = {
    seed?: Uint8Array;
    storage?: ISignerStorage;
    session?: Partial<SessionOptions>;
    tamper?: (outcome: DispatchOutcome) => DispatchOutcome;
};

const bridges: InMemorySignerBridge[] = [];

afterEach(() => {
    for (const bridge of bridges.splice(0)) expect(bridge.violations).toEqual([]);
});

function newBridge(): InMemorySignerBridge {
    const bridge = new InMemorySignerBridge(PEER_KEYS);
    bridges.push(bridge);
    return bridge;
}

function device(bridge: InMemorySignerBridge, options: DeviceOptions = {}): Device {
    const seed = options.seed ?? MASTER_SEED;
    const store = new SignerStore(options.storage ?? new InMemorySignerStorage());
    const policy = new PolicyEngine(store);
    const dispatch = new SignerDispatch({ masterSeed: seed, commitmentLock: COMMITMENT_LOCK_TESTNET, policy });
    const outcomes: Promise<DispatchOutcome>[] = [];
    const handler: ISessionHandler = {
        handle(request) {
            const outcome = dispatch.handle(request);
            outcomes.push(outcome);
            return options.tamper ? outcome.then(options.tamper) : outcome;
        },
        channelRegistered: (channelId, pending) => dispatch.channelRegistered(channelId, pending),
    };
    const timer = new TimerMock();
    const events: SessionEvent[] = [];
    const session = new SignerSession({
        url: URL,
        createWebSocket: bridge.createWebSocket,
        timer,
        authenticator: new WalletIdentity(seed),
        handler,
        random: () => 1,
        reconnect: { initialDelayMs: RECONNECT_DELAY_MS },
        heartbeatIntervalMs: 0,
        ...options.session,
    });
    session.onEvent((event) => events.push(event));
    const errors = (): unknown[] => events.flatMap((event) => (event.type === "error" ? [event.cause] : []));
    return { session, dispatch, policy, store, timer, outcomes, events, errors };
}

async function connected(bridge: InMemorySignerBridge, options: DeviceOptions = {}): Promise<Device> {
    const d = device(bridge, options);
    await d.session.connect();
    return d;
}

function openChannel(d: Device, channelIndex = CHANNEL_INDEX, exposure = OPENING_EXPOSURE): Promise<string> {
    return d.session.registerChannel(d.dispatch.prepareChannelRegistration(channelIndex, exposure));
}

function signed(outcome: BridgeSignOutcome): Extract<BridgeSignOutcome, { kind: "signed" }> {
    if (outcome.kind !== "signed") throw new Error(`the device refused: ${outcome.error.code}, ${outcome.error.message}`);
    return outcome;
}

function partialSignatureOf(outcome: DispatchOutcome): Uint8Array {
    if (outcome.kind !== "result" || outcome.result.kind !== "partial_signature") throw new Error("not a partial signature");
    return outcome.result.partialSignature;
}

function flipPartialSignature(outcome: DispatchOutcome): DispatchOutcome {
    if (outcome.kind !== "result" || outcome.result.kind !== "partial_signature") return outcome;
    const partialSignature = outcome.result.partialSignature.map((byte, index, bytes) => (index === bytes.length - 1 ? byte ^ 1 : byte));
    return { kind: "result", result: { kind: "partial_signature", partialSignature } };
}

function standInSession(digestHex: string): SignSessionWire {
    return toSignSessionWire([bytesToHex(LOCAL_FUNDING_PUBKEY), REMOTE.funding_pubkey], bytesToHex(STAND_IN_NONCE), digestHex);
}

describe("the session against the bridge", () => {
    it("establishes: the bridge verifies the signed challenge over the domain-separated digest and pins the identity", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        expect(d.session.state).toBe("established");
        expect(bridge.identityKey).toEqual(new WalletIdentity(MASTER_SEED).publicKey);
        expect(bridge.delivered).toEqual([
            { type: "challenge", challenge: expect.stringMatching(/^0x[0-9a-f]{64}$/) },
            { type: "session_established", protocol_version: PROTOCOL_VERSION, pending_requests: 0 },
        ]);
        expect(bridge.refusals).toEqual([]);
        expect(d.errors()).toEqual([]);
    });

    it("accepts a device restored from the same seed under the identity it pinned", async () => {
        const bridge = newBridge();
        const first = await connected(bridge);
        first.session.disconnect();
        const restored = await connected(bridge);
        expect(restored.session.state).toBe("established");
        expect(bridge.refusals).toEqual([]);
        expect(bridge.identityKey).toEqual(new WalletIdentity(MASTER_SEED).publicKey);
    });

    it("refuses a device presenting another identity: the bridge hangs up on the signature, read as handshake_refused", async () => {
        const bridge = newBridge();
        (await connected(bridge)).session.disconnect();
        const other = device(bridge, { seed: OTHER_SEED });
        sessionError(await rejection(other.session.connect()), "handshake_refused");
        expect(bridge.refusals).toEqual(["the identity is not the one pinned"]);
        expect(bridge.identityKey).toEqual(new WalletIdentity(MASTER_SEED).publicKey);
        expect(other.session.state).toBe("closed");
        expect(other.timer.pending).toBe(0);
    });

    it("ends the session on a bridge that speaks another protocol version", async () => {
        const bridge = newBridge();
        bridge.protocolVersion = PROTOCOL_VERSION + 1;
        const d = device(bridge);
        sessionError(await rejection(d.session.connect()), "version_mismatch");
        expect(d.session.state).toBe("closed");
        expect(bridge.hasSession).toBe(false);
    });

    it("queues what the node asks while the device is offline and drains it in order on the next session", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);
        d.session.disconnect();
        expect(bridge.hasSession).toBe(false);

        const point = bridge.commitmentPoint(channelId, 1);
        const nonce = bridge.pubNonce(channelId, "COMMITMENT", 0);
        expect(bridge.pendingRequests).toBe(2);

        await d.session.connect();
        await expect(point).resolves.toEqual(getChannelCommitmentPoint(KEYS, 1));
        await expect(nonce).resolves.toEqual(getPublicNonce(KEYS, 0, "COMMITMENT"));
        expect(bridge.delivered.slice(-3)).toEqual([
            { type: "session_established", protocol_version: PROTOCOL_VERSION, pending_requests: 2 },
            expect.objectContaining({ type: "sign_request", method: "get_commitment_point" }),
            expect.objectContaining({ type: "sign_request", method: "get_commitment_pub_nonce" }),
        ]);
        expect(bridge.pendingRequests).toBe(0);
        expect(d.errors()).toEqual([]);
    });

    it("keeps the session alive by heartbeat in both directions", async () => {
        const bridge = newBridge();
        const d = await connected(bridge, { session: HEARTBEAT });
        d.timer.advance(HEARTBEAT.heartbeatIntervalMs);
        await flush();
        expect(bridge.pingsReceived).toBe(1);
        d.timer.advance(HEARTBEAT.heartbeatTimeoutMs);
        expect(d.session.state).toBe("established");
        await bridge.ping();
        expect(d.session.state).toBe("established");
        expect(d.errors()).toEqual([]);
    });
});

describe("channel open", () => {
    it("registers the channel under the name the bridge gives it, delegating the TLC base key and never the funding key", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);

        const channelId = await openChannel(d);

        expect(channelId).toMatch(/^0x[0-9a-f]{64}$/);
        expect(bridge.channels.get(channelId)).toEqual({
            fundingPubkey: LOCAL_FUNDING_PUBKEY,
            tlcBasePubkey: pubkeyOf(KEYS.tlcBaseKey),
            localSettlementKey: KEYS.tlcBaseKey,
            stateVersion: 0,
        });
        const sent = JSON.stringify(bridge.factory.sockets.flatMap((socket) => socket.sent));
        // Proves the search finds a key written this way.
        expect(sent).toContain(bytesToHex(KEYS.tlcBaseKey));
        expect(sent).not.toContain(bytesToHex(KEYS.fundingKey));
        await expect(d.store.resolveChannelIndex(channelId)).resolves.toBe(CHANNEL_INDEX);
        await expect(d.store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual({
            version: CHANNEL_POLICY_RECORD_VERSION,
            channelId,
            lastSignedCommitmentNumbers: {},
            signedSessions: {},
            lastStateVersion: 0,
            localExposureShannons: OPENING_EXPOSURE,
            pendingDebitsShannons: [],
        });
    });

    it("lets the node fetch what OpenChannel needs by number, once the channel is named", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);

        await expect(bridge.publicKeys(channelId)).resolves.toEqual(getBasePublicKeys(KEYS));
        await expect(bridge.commitmentPoint(channelId, 1)).resolves.toEqual(getChannelCommitmentPoint(KEYS, 1));
        await expect(bridge.commitmentPoint(channelId, 2)).resolves.toEqual(getChannelCommitmentPoint(KEYS, 2));
        await expect(bridge.pubNonce(channelId, "COMMITMENT", 0)).resolves.toEqual(getPublicNonce(KEYS, 0, "COMMITMENT"));
        await expect(bridge.pubNonce(channelId, "REVOKE", 2)).resolves.toEqual(getPublicNonce(KEYS, 2, "REVOKE"));
        await expect(bridge.pubNonce(channelId, "ANNOUNCEMENT", undefined)).resolves.toEqual(
            getPublicNonce(KEYS, ANNOUNCEMENT_SLOT_NUMBER, "ANNOUNCEMENT"),
        );
        expect(d.errors()).toEqual([]);
    });

    it("signs the first commitment, which the node verifies and aggregates into a signature the 2-of-2 key accepts", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);

        const { signature } = signed(await bridge.signCommitmentTx(channelId, OPEN));

        const aggregateKey = keyAggExport(keyAggregate([LOCAL_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY].sort(compareBytes)));
        expect(schnorr.verify(signature, hexToBytes(OPEN.digest), aggregateKey)).toBe(true);
        await expect(d.store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual({
            version: CHANNEL_POLICY_RECORD_VERSION,
            channelId,
            lastSignedCommitmentNumbers: { COMMITMENT: OPEN.commitment_number },
            signedSessions: { [`COMMITMENT:${OPEN.commitment_number}`]: SESSION_COMMITMENT },
            lastStateVersion: 1,
            localExposureShannons: OPENING_EXPOSURE,
            pendingDebitsShannons: [],
        });
        expect(d.errors()).toEqual([]);
    });

    it("rejects a registration the bridge refuses with the bridge's own code, filing nothing", async () => {
        const bridge = newBridge();
        const storage = new InMemorySignerStorage();
        const d = await connected(bridge, { storage });
        bridge.registrationError = { code: "channel_limit", message: "no more channels for this account" };

        const error = await rejection(openChannel(d));

        expect(error).toBeInstanceOf(BridgeError);
        expect(error).toMatchObject({ code: "channel_limit", message: "no more channels for this account" });
        expect(bridge.channels.size).toBe(0);
        expect(storage.map.size).toBe(0);
        expect(d.session.state).toBe("established");
    });
});

describe("the life of a channel", () => {
    it("signs every kind of message over the wire, each verified and aggregated by the node", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);

        signed(await bridge.signCommitmentTx(channelId, OPEN));
        await d.policy.recordDebitIntent(channelId, SEND_DECREASE);
        signed(await bridge.signCommitmentTx(channelId, SEND));
        signed(await bridge.signRevocation(channelId, SEND_SIDE_REVOCATION));
        signed(await bridge.signClosingTx(channelId, CLOSE));
        signed(await bridge.signChannelAnnouncement(channelId, ANNOUNCEMENT));

        await expect(d.store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual({
            version: CHANNEL_POLICY_RECORD_VERSION,
            channelId,
            lastSignedCommitmentNumbers: {
                COMMITMENT: SHUTDOWN_NONCE_NUMBER,
                REVOKE: REVOCATION_NONCE_NUMBER,
                ANNOUNCEMENT: ANNOUNCEMENT_SLOT_NUMBER,
            },
            signedSessions: {
                [`COMMITMENT:${OPEN.commitment_number}`]: SESSION_COMMITMENT,
                [`COMMITMENT:${SEND.commitment_number}`]: SESSION_COMMITMENT,
                [`COMMITMENT:${SHUTDOWN_NONCE_NUMBER}`]: SESSION_COMMITMENT,
                [`REVOKE:${REVOCATION_NONCE_NUMBER}`]: SESSION_COMMITMENT,
                [`ANNOUNCEMENT:${ANNOUNCEMENT_SLOT_NUMBER}`]: SESSION_COMMITMENT,
            },
            lastStateVersion: 5,
            localExposureShannons: CLOSE.to_local,
            pendingDebitsShannons: [],
        });
        expect(bridge.pendingRequests).toBe(0);
        expect(d.errors()).toEqual([]);
    });
});

describe("re-delivery", () => {
    function isCommitmentSignRequest(frame: { type: string; method?: string }): boolean {
        return frame.type === "sign_request" && frame.method === "partial_sign_commitment_tx";
    }

    it("answers a request re-delivered after the socket was lost mid-round with the same bytes, writing nothing", async () => {
        const bridge = newBridge();
        const storage = new InMemorySignerStorage();
        const d = await connected(bridge, { storage });
        const channelId = await openChannel(d);
        signed(await bridge.signCommitmentTx(channelId, OPEN));
        await d.policy.recordDebitIntent(channelId, SEND_DECREASE);
        bridge.dropAfter = isCommitmentSignRequest;

        const round = bridge.signCommitmentTx(channelId, SEND);
        await flush();

        const dropped = await d.outcomes[d.outcomes.length - 1];
        expect(dropped?.kind).toBe("result");
        expect(d.session.state).toBe("reconnecting");
        expect(bridge.pendingRequests).toBe(1);
        await expect(d.store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pendingDebitsShannons: [] });
        await d.policy.recordDebitIntent(channelId, SEND_DECREASE);
        storage.ops.length = 0;

        d.timer.advance(RECONNECT_DELAY_MS);
        const { partialSignature } = signed(await round);

        expect(partialSignature).toEqual(partialSignatureOf(dropped as DispatchOutcome));
        expect(storage.ops.filter((op) => op.startsWith("set "))).toEqual([]);
        const deliveries = bridge.delivered.filter(isCommitmentSignRequest);
        expect(deliveries).toHaveLength(3);
        expect(deliveries[2]).toEqual(deliveries[1]);
        expect(bridge.factory.sockets).toHaveLength(2);
        await expect(d.store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            pendingDebitsShannons: [SEND_DECREASE],
            localExposureShannons: SEND.settlement_local,
        });
        expect(bridge.pendingRequests).toBe(0);
    });

    it("leaves a request the device cannot evaluate unanswered, answers the next, and answers it on re-delivery once the cause is gone", async () => {
        const bridge = newBridge();
        const inner = new InMemorySignerStorage();
        const cause = new Error("storage unavailable");
        let failures = 0;
        const storage: ISignerStorage = {
            get(key) {
                if (failures > 0) {
                    failures -= 1;
                    throw cause;
                }
                return inner.get(key);
            },
            set(key, value) {
                inner.set(key, value);
            },
        };
        const d = await connected(bridge, { storage });
        const channelId = await openChannel(d);
        failures = 1;

        const round = bridge.signCommitmentTx(channelId, OPEN);
        await flush();

        expect(d.errors()).toEqual([cause]);
        expect(bridge.pendingRequests).toBe(1);
        expect(d.session.state).toBe("established");
        await expect(bridge.commitmentPoint(channelId, 1)).resolves.toEqual(getChannelCommitmentPoint(KEYS, 1));

        bridge.dropConnection();
        await flush();
        d.timer.advance(RECONNECT_DELAY_MS);
        signed(await round);

        const nonceRequests = bridge.delivered.filter(
            (frame) => frame.type === "sign_request" && frame.method === "get_commitment_pub_nonce",
        );
        expect(nonceRequests).toHaveLength(2);
        expect(nonceRequests[1]).toEqual(nonceRequests[0]);
        expect(bridge.pendingRequests).toBe(0);
    });
});

describe("refusals", () => {
    it("answers a refusal and stalls nothing queued behind it: neither the other channel nor the next request on the same one", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);
        const otherChannelId = await openChannel(d, OTHER_CHANNEL_INDEX);
        expect(otherChannelId).not.toBe(channelId);

        // Sent whole rather than as a round, so it reaches the device before the two requests queued behind it.
        const refused = bridge.request(channelId, {
            method: "partial_sign_commitment_tx",
            params: toPartialSignCommitmentTxParamsWire(SEND, REMOTE, standInSession(SEND.digest), SEND.commitment_number),
        });
        const otherNonce = bridge.pubNonce(otherChannelId, "COMMITMENT", 0);
        const round = bridge.signCommitmentTx(channelId, OPEN);

        await expect(refused).resolves.toEqual({
            error: { code: "policy_refusal", message: expect.stringContaining("no debit intent") },
        });
        await expect(otherNonce).resolves.toEqual(getPublicNonce(OTHER_KEYS, 0, "COMMITMENT"));
        signed(await round);
        expect(bridge.delivered.flatMap((frame) => (frame.type === "sign_request" ? [[frame.channel_id, frame.method]] : []))).toEqual([
            [channelId, "partial_sign_commitment_tx"],
            [otherChannelId, "get_commitment_pub_nonce"],
            [channelId, "get_commitment_pub_nonce"],
            [channelId, "partial_sign_commitment_tx"],
        ]);
        expect(bridge.pendingRequests).toBe(0);
        expect(d.errors()).toEqual([]);
    });

    it("answers a request with a field the device cannot read as malformed, naming the field", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);

        const answer = await bridge.request(channelId, { method: "get_commitment_point", params: { commitment_number: "0X1" } });

        expect(answer).toEqual({
            error: { code: "malformed", message: expect.stringContaining("sign_request.params.commitment_number") },
        });
        expect(JSON.stringify(answer)).not.toContain("0X1");
        await expect(bridge.commitmentPoint(channelId, 1)).resolves.toEqual(getChannelCommitmentPoint(KEYS, 1));
    });
});

describe("a wiped device", () => {
    it("refuses every request for a channel registered before the wipe as unknown_channel, writing nothing", async () => {
        const bridge = newBridge();
        const before = await connected(bridge);
        const channelId = await openChannel(before);
        signed(await bridge.signCommitmentTx(channelId, OPEN));
        before.session.disconnect();

        const storage = new InMemorySignerStorage();
        const after = await connected(bridge, { storage });
        expect(bridge.refusals).toEqual([]);

        const session = standInSession(OPEN.digest);
        const requests: SignMethodParamsWire[] = [
            { method: "get_base_public_keys", params: {} },
            { method: "get_commitment_point", params: toCommitmentNumberParamsWire(1) },
            { method: "get_commitment_pub_nonce", params: toCommitmentNumberParamsWire(0) },
            { method: "get_revocation_pub_nonce", params: toCommitmentNumberParamsWire(2) },
            { method: "get_channel_announcement_pub_nonce", params: {} },
            { method: "get_settlement_keys", params: toCommitmentNumberParamsWire(0) },
            {
                method: "partial_sign_commitment_tx",
                params: toPartialSignCommitmentTxParamsWire(OPEN, REMOTE, session, OPEN.commitment_number),
            },
            { method: "partial_sign_closing_tx", params: toPartialSignClosingTxParamsWire(CLOSE, REMOTE, session, SHUTDOWN_NONCE_NUMBER) },
            {
                method: "partial_sign_revocation",
                params: toPartialSignRevocationParamsWire(SEND_SIDE_REVOCATION, REMOTE, session, REVOCATION_NONCE_NUMBER),
            },
            {
                method: "partial_sign_channel_announcement",
                params: toPartialSignChannelAnnouncementParamsWire(ANNOUNCEMENT, REMOTE, session),
            },
        ];
        expect(requests.map((request) => request.method)).toEqual([...SIGNER_METHODS]);

        for (const request of requests) {
            await expect(bridge.request(channelId, request)).resolves.toEqual({
                error: { code: "unknown_channel", message: expect.stringContaining(channelId) },
            });
        }
        expect(storage.map.size).toBe(0);
        expect(after.errors()).toEqual([]);
        expect(bridge.identityKey).toEqual(new WalletIdentity(MASTER_SEED).publicKey);
    });
});

describe("the bridge's own checks", () => {
    it("refuses a signature over the bare challenge, verifying over the domain-separated digest", async () => {
        const bridge = newBridge();
        const identityKey = deriveWalletIdentityKey(MASTER_SEED);
        const bare: ISessionAuthenticator = {
            publicKey: schnorr.getPublicKey(identityKey),
            signChallenge: (challenge) => schnorr.sign(challenge, identityKey, new Uint8Array(32)),
        };
        const d = device(bridge, { session: { authenticator: bare } });

        sessionError(await rejection(d.session.connect()), "handshake_refused");
        expect(bridge.refusals).toEqual(["the signature does not verify"]);
        expect(bridge.identityKey).toBeUndefined();
    });

    it("rejects only the round whose partial signature does not verify, leaving the session up", async () => {
        const bridge = newBridge();
        const d = await connected(bridge, { tamper: flipPartialSignature });
        const channelId = await openChannel(d);

        await expect(bridge.signCommitmentTx(channelId, OPEN)).rejects.toThrow(
            "the device's partial signature does not verify under the aggregate the node built",
        );

        expect(d.session.state).toBe("established");
        expect(bridge.hasSession).toBe(true);
        expect(bridge.pendingRequests).toBe(0);
        await expect(bridge.commitmentPoint(channelId, 1)).resolves.toEqual(getChannelCommitmentPoint(KEYS, 1));
    });

    it("records an answer to a request it never sent as a violation, hanging up and rejecting what it waits on", async () => {
        const bridge = newBridge();
        const d = await connected(bridge);
        const channelId = await openChannel(d);
        const diagnosis = "the device answered a request the bridge is not waiting on: 0xff";

        const point = bridge.commitmentPoint(channelId, 1);
        // Forged on the device's socket: the session never answers an id it was not asked.
        bridge.factory.last.send(JSON.stringify({ type: "sign_response", request_id: "0xff", result: { commitment_point: "0x00" } }));

        await expect(point).rejects.toThrow(diagnosis);
        await expect(bridge.pubNonce(channelId, "COMMITMENT", 0)).rejects.toThrow(diagnosis);
        await flush();
        expect(bridge.hasSession).toBe(false);
        expect(d.session.state).toBe("reconnecting");
        expect(d.errors()).toHaveLength(1);
        expect(sessionError(d.errors()[0], "connection_lost").message).toContain("code 1002");
        expect(bridge.violations.splice(0).map((violation) => violation.message)).toEqual([diagnosis]);
    });

    it("records a delegated settlement key that is not the TLC base key as a violation, hanging up on the registration", async () => {
        const bridge = newBridge();
        const storage = new InMemorySignerStorage();
        const d = await connected(bridge, { storage });
        const pending = d.dispatch.prepareChannelRegistration(CHANNEL_INDEX, OPENING_EXPOSURE);
        const misdelegated = { ...pending, registration: { ...pending.registration, localSettlementKey: OTHER_KEYS.tlcBaseKey } };

        const error = sessionError(await rejection(d.session.registerChannel(misdelegated)), "connection_lost");

        expect(error.message).toContain("code 1002");
        expect(d.session.state).toBe("reconnecting");
        expect(bridge.channels.size).toBe(0);
        expect(storage.map.size).toBe(0);
        expect(bridge.violations.splice(0).map((violation) => violation.message)).toEqual([
            "the delegated settlement key is not the TLC base key",
        ]);
    });
});
