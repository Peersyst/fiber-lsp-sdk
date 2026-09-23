import { schnorr } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Session, keyAggExport, keyAggregate, nonceAggregate, nonceGen } from "@scure/btc-signer/musig2.js";
import { ckbBlake2b, compareBytes } from "../../src/common";
import type { FiberChannelKeys, NonceContext } from "../../src/derivation";
import { deriveNonceSeed, pubkeyOf } from "../../src/derivation";
import { ANNOUNCEMENT_SLOT_NUMBER } from "../../src/policy";
import type {
    InboundFrameWire,
    SignError,
    SignMethodParamsWire,
    SignRequestWire,
    SignResultWire,
    SignSessionWire,
} from "../../src/protocol";
import { PROTOCOL_VERSION, sessionChallengeDigest } from "../../src/protocol";
import type { WebSocketFactory } from "../../src/session";
import { WebSocketFactoryMock, WebSocketMock } from "../mocks/session";
import type { RemotePubkeys } from "./digest-inputs";
import type { AnnouncementCaseVector, CommitmentCaseVector, RevocationCaseVector, ShutdownCaseVector } from "./interop-vectors";
import { SHUTDOWN_NONCE_NUMBER, revocationNonceNumber } from "./nonce-numbers";
import {
    toCommitmentNumberParamsWire,
    toPartialSignChannelAnnouncementParamsWire,
    toPartialSignClosingTxParamsWire,
    toPartialSignCommitmentTxParamsWire,
    toPartialSignRevocationParamsWire,
    toSignRequestWire,
    toSignSessionWire,
    wireHex,
} from "./wire-requests";

export type RegisteredChannel = {
    fundingPubkey: Uint8Array;
    tlcBasePubkey: Uint8Array;
    localSettlementKey: Uint8Array;
    stateVersion: number;
};

export type BridgeAnswer = { result: SignResultWire } | { error: SignError };

export type BridgeSignOutcome =
    { kind: "signed"; partialSignature: Uint8Array; signature: Uint8Array } | { kind: "refused"; error: SignError };

type DeviceFrame = Record<string, unknown> & { type: string };

type Waiter<T> = { resolve: (value: T) => void; reject: (error: Error) => void };

type Pending = Waiter<BridgeAnswer> & { frame: SignRequestWire };

const REFUSED_CLOSE_CODE = 1008;

const LOST_CLOSE_CODE = 1006;

const VIOLATION_CLOSE_CODE = 1002;

export class InMemorySignerBridge {
    readonly factory = new WebSocketFactoryMock();

    readonly createWebSocket: WebSocketFactory = (url) => {
        const socket = this.factory.create(url);
        this.accept(socket);
        return socket;
    };

    protocolVersion = PROTOCOL_VERSION;

    identityKey: Uint8Array | undefined;

    readonly channels = new Map<string, RegisteredChannel>();

    readonly delivered: InboundFrameWire[] = [];

    readonly refusals: string[] = [];

    readonly violations: Error[] = [];

    pingsReceived = 0;

    registrationError: { code: string; message: string } | undefined;

    /**
     * One shot: cleared once it drops a socket.
     */
    dropAfter: ((frame: InboundFrameWire) => boolean) | undefined;

    private readonly remote: RemotePubkeys;

    private readonly peer: FiberChannelKeys;

    private readonly peerFundingPubkey: Uint8Array;

    private socket: WebSocketMock | undefined;

    private readonly pending = new Map<string, Pending>();

    private readonly pongWaiters: Waiter<void>[] = [];

    private requests = 0;

    private challenges = 0;

    constructor(peer: FiberChannelKeys) {
        this.peer = peer;
        this.peerFundingPubkey = pubkeyOf(peer.fundingKey);
        this.remote = { funding_pubkey: bytesToHex(this.peerFundingPubkey), tlc_base_pubkey: bytesToHex(pubkeyOf(peer.tlcBaseKey)) };
    }

    get hasSession(): boolean {
        return this.socket !== undefined;
    }

    get pendingRequests(): number {
        return this.pending.size;
    }

    dropConnection(): void {
        this.drop(this.session());
    }

    ping(): Promise<void> {
        const socket = this.session();
        return this.waiting<void>((waiter) => {
            this.pongWaiters.push(waiter);
            this.deliver(socket, { type: "ping" });
        });
    }

    request(
        channelId: string,
        request: SignMethodParamsWire,
        stateVersion = this.channels.get(channelId)?.stateVersion ?? 0,
    ): Promise<BridgeAnswer> {
        const requestId = wireHex((++this.requests).toString(16));
        const frame = toSignRequestWire({ requestId, channelId, stateVersion }, request);
        return this.waiting((waiter) => {
            this.pending.set(requestId, { frame, ...waiter });
            if (this.socket) this.deliver(this.socket, frame);
        });
    }

    publicKeys(channelId: string): Promise<{ fundingPubkey: Uint8Array; tlcBasePubkey: Uint8Array }> {
        const answer = this.result(channelId, { method: "get_base_public_keys", params: {} });
        return observed(
            answer.then((result) => ({
                fundingPubkey: resultBytes(result, "funding_pubkey"),
                tlcBasePubkey: resultBytes(result, "tlc_base_pubkey"),
            })),
        );
    }

    commitmentPoint(channelId: string, commitmentNumber: number): Promise<Uint8Array> {
        const answer = this.result(channelId, { method: "get_commitment_point", params: toCommitmentNumberParamsWire(commitmentNumber) });
        return observed(answer.then((result) => resultBytes(result, "commitment_point")));
    }

    pubNonce(channelId: string, context: NonceContext, commitmentNumber: number | undefined): Promise<Uint8Array> {
        const answer = this.result(channelId, nonceRequest(context, commitmentNumber));
        return observed(answer.then((result) => resultBytes(result, "pub_nonce")));
    }

    signCommitmentTx(channelId: string, kase: CommitmentCaseVector): Promise<BridgeSignOutcome> {
        const number = kase.commitment_number;
        return observed(
            this.round(channelId, "COMMITMENT", number, this.sortedKeys(channelId), kase.digest, (session) => ({
                method: "partial_sign_commitment_tx",
                params: toPartialSignCommitmentTxParamsWire(kase, this.remote, session, number),
            })),
        );
    }

    signClosingTx(channelId: string, kase: ShutdownCaseVector): Promise<BridgeSignOutcome> {
        return observed(
            this.round(channelId, "COMMITMENT", SHUTDOWN_NONCE_NUMBER, this.sortedKeys(channelId), kase.digest, (session) => ({
                method: "partial_sign_closing_tx",
                params: toPartialSignClosingTxParamsWire(kase, this.remote, session, SHUTDOWN_NONCE_NUMBER),
            })),
        );
    }

    signRevocation(channelId: string, kase: RevocationCaseVector): Promise<BridgeSignOutcome> {
        const number = revocationNonceNumber(kase);
        // Fiber orders a revocation's keys by role rather than sorting them.
        const device = this.channel(channelId).fundingPubkey;
        const orderedPubkeys = kase.for_remote ? [device, this.peerFundingPubkey] : [this.peerFundingPubkey, device];
        return observed(
            this.round(channelId, "REVOKE", number, orderedPubkeys, kase.digest, (session) => ({
                method: "partial_sign_revocation",
                params: toPartialSignRevocationParamsWire(kase, this.remote, session, number),
            })),
        );
    }

    signChannelAnnouncement(channelId: string, kase: AnnouncementCaseVector): Promise<BridgeSignOutcome> {
        return observed(
            this.round(channelId, "ANNOUNCEMENT", undefined, this.sortedKeys(channelId), kase.digest, (session) => ({
                method: "partial_sign_channel_announcement",
                params: toPartialSignChannelAnnouncementParamsWire(kase, this.remote, session),
            })),
        );
    }

    private async round(
        channelId: string,
        context: NonceContext,
        commitmentNumber: number | undefined,
        orderedPubkeys: Uint8Array[],
        digestHex: string,
        build: (session: SignSessionWire) => SignMethodParamsWire,
    ): Promise<BridgeSignOutcome> {
        const stateVersion = ++this.channel(channelId).stateVersion;
        const nonce = await this.request(channelId, nonceRequest(context, commitmentNumber), stateVersion);
        if ("error" in nonce) return { kind: "refused", error: nonce.error };
        const deviceNonce = resultBytes(nonce.result, "pub_nonce");
        const deviceIndex = orderedPubkeys.findIndex((key) => !equalBytes(key, this.peerFundingPubkey));
        const peerNonce = () => this.peerNonce(context, commitmentNumber ?? ANNOUNCEMENT_SLOT_NUMBER);
        const pubNonces = orderedPubkeys.map((_, index) => (index === deviceIndex ? deviceNonce : peerNonce().public));
        const aggregatedNonce = nonceAggregate(pubNonces);
        const [first, second] = orderedPubkeys as [Uint8Array, Uint8Array];
        const session = toSignSessionWire([bytesToHex(first), bytesToHex(second)], bytesToHex(aggregatedNonce), digestHex);

        const answer = await this.request(channelId, build(session), stateVersion);
        if ("error" in answer) return { kind: "refused", error: answer.error };
        const partialSignature = resultBytes(answer.result, "partial_signature");

        const message = hexToBytes(digestHex);
        const musig = new Session(aggregatedNonce, orderedPubkeys, message);
        if (!musig.partialSigVerify(partialSignature, pubNonces, deviceIndex)) {
            throw new Error("the device's partial signature does not verify under the aggregate the node built");
        }
        const peerPartialSignature = musig.sign(peerNonce().secret, this.peer.fundingKey);
        const partials = orderedPubkeys.map((_, index) => (index === deviceIndex ? partialSignature : peerPartialSignature));
        const signature = musig.partialSigAgg(partials);
        if (!schnorr.verify(signature, message, keyAggExport(keyAggregate(orderedPubkeys)))) {
            throw new Error("the aggregated signature does not verify under the 2-of-2 key");
        }
        return { kind: "signed", partialSignature, signature };
    }

    private async result(channelId: string, request: SignMethodParamsWire): Promise<SignResultWire> {
        const answer = await this.request(channelId, request);
        if ("error" in answer) throw new Error(`the device refused ${request.method}: ${answer.error.code}, ${answer.error.message}`);
        return answer.result;
    }

    private waiting<T>(register: (waiter: Waiter<T>) => void): Promise<T> {
        const violation = this.violations[0];
        if (violation) return observed(Promise.reject(violation));
        return observed(new Promise((resolve, reject) => register({ resolve, reject })));
    }

    private peerNonce(context: NonceContext, commitmentNumber: number) {
        const seed = deriveNonceSeed(this.peer, commitmentNumber, context);
        return nonceGen(this.peerFundingPubkey, this.peer.fundingKey, undefined, undefined, undefined, seed);
    }

    private sortedKeys(channelId: string): Uint8Array[] {
        return [this.channel(channelId).fundingPubkey, this.peerFundingPubkey].sort(compareBytes);
    }

    private channel(channelId: string): RegisteredChannel {
        const channel = this.channels.get(channelId);
        if (!channel) throw new Error(`the bridge knows no channel ${channelId}`);
        return channel;
    }

    private session(): WebSocketMock {
        if (!this.socket) throw new Error("the bridge has no session");
        return this.socket;
    }

    private accept(socket: WebSocketMock): void {
        const challenge = ckbBlake2b(utf8ToBytes(`challenge ${++this.challenges}`));
        socket.onSent = (frame) => {
            try {
                this.onDeviceFrame(socket, challenge, deviceFrame(frame));
            } catch (error) {
                this.violate(socket, error instanceof Error ? error : new Error(String(error)));
            }
        };
        socket.onClosed = () => this.detach(socket);
        this.deliver(socket, { type: "challenge", challenge: wireHex(bytesToHex(challenge)) });
    }

    private onDeviceFrame(socket: WebSocketMock, challenge: Uint8Array, frame: DeviceFrame): void {
        if (socket !== this.socket) {
            if (frame.type !== "signed_challenge") throw new Error(`the device sent ${frame.type} before authenticating`);
            this.authenticate(socket, challenge, frame);
            return;
        }
        switch (frame.type) {
            case "sign_response":
                this.settle(frame);
                return;
            case "register_channel":
                this.register(socket, frame);
                return;
            case "ping":
                this.pingsReceived += 1;
                this.deliver(socket, { type: "pong" });
                return;
            case "pong":
                this.pongWaiters.shift()?.resolve();
                return;
            default:
                throw new Error(`the device sent an unexpected ${frame.type} frame`);
        }
    }

    private authenticate(socket: WebSocketMock, challenge: Uint8Array, frame: DeviceFrame): void {
        const publicKey = hexField(frame, "public_key");
        const signature = hexField(frame, "signature");
        if (!schnorr.verify(signature, sessionChallengeDigest(challenge), publicKey)) {
            this.refuse(socket, "the signature does not verify");
            return;
        }
        if (this.identityKey && !equalBytes(this.identityKey, publicKey)) {
            this.refuse(socket, "the identity is not the one pinned");
            return;
        }
        this.identityKey = publicKey;
        this.socket = socket;
        this.deliver(socket, { type: "session_established", protocol_version: this.protocolVersion, pending_requests: this.pending.size });
        for (const { frame: request } of this.pending.values()) {
            if (this.socket !== socket) break;
            this.deliver(socket, request);
        }
    }

    private settle(frame: DeviceFrame): void {
        const requestId = stringField(frame, "request_id");
        const pending = this.pending.get(requestId);
        if (!pending) throw new Error(`the device answered a request the bridge is not waiting on: ${requestId}`);
        if ("error" in frame) pending.resolve({ error: frame.error as SignError });
        else if ("result" in frame) pending.resolve({ result: frame.result as SignResultWire });
        else throw new Error(`the device's sign_response ${requestId} carries neither a result nor an error`);
        this.pending.delete(requestId);
    }

    private register(socket: WebSocketMock, frame: DeviceFrame): void {
        const requestId = stringField(frame, "request_id");
        const refusal = this.registrationError;
        if (refusal) {
            this.registrationError = undefined;
            this.deliver(socket, { type: "error", request_id: requestId, ...refusal });
            return;
        }
        const fundingPubkey = hexField(frame, "funding_pubkey");
        const tlcBasePubkey = hexField(frame, "tlc_base_pubkey");
        const localSettlementKey = hexField(frame, "local_settlement_key");
        if (!equalBytes(pubkeyOf(localSettlementKey), tlcBasePubkey))
            throw new Error("the delegated settlement key is not the TLC base key");
        const channelId = tempChannelId(tlcBasePubkey);
        const stateVersion = this.channels.get(channelId)?.stateVersion ?? 0;
        this.channels.set(channelId, { fundingPubkey, tlcBasePubkey, localSettlementKey, stateVersion });
        this.deliver(socket, { type: "channel_registered", request_id: requestId, channel_id: channelId });
    }

    private refuse(socket: WebSocketMock, reason: string): void {
        this.refusals.push(reason);
        this.forget(socket);
        void socket.closeFromServer(REFUSED_CLOSE_CODE, reason);
    }

    private violate(socket: WebSocketMock, violation: Error): void {
        // The session swallows what its send throws, so the waiters and the hang-up report it.
        this.violations.push(violation);
        this.forget(socket);
        void socket.closeFromServer(VIOLATION_CLOSE_CODE, violation.message);
        for (const waiter of [...this.pending.values(), ...this.pongWaiters.splice(0)]) waiter.reject(violation);
        this.pending.clear();
    }

    private drop(socket: WebSocketMock): void {
        this.forget(socket);
        void socket.closeFromServer(LOST_CLOSE_CODE, "connection lost");
    }

    private forget(socket: WebSocketMock): void {
        socket.onSent = null;
        socket.onClosed = null;
        this.detach(socket);
    }

    private detach(socket: WebSocketMock): void {
        if (socket === this.socket) this.socket = undefined;
    }

    private deliver(socket: WebSocketMock, frame: InboundFrameWire): void {
        this.delivered.push(frame);
        void socket.receive(frame);
        if (this.dropAfter?.(frame)) {
            this.dropAfter = undefined;
            this.drop(socket);
        }
    }
}

// A test that fails on one rejection leaves the rest unawaited, and an unhandled rejection ends the whole run.
function observed<T>(promise: Promise<T>): Promise<T> {
    promise.catch(() => undefined);
    return promise;
}

function nonceRequest(context: NonceContext, commitmentNumber: number | undefined): SignMethodParamsWire {
    if (context === "ANNOUNCEMENT") return { method: "get_channel_announcement_pub_nonce", params: {} };
    if (context === "CLOSE") throw new Error("no method fetches a CLOSE nonce: the context is reserved and unused");
    if (commitmentNumber === undefined) throw new Error(`the node fetches a ${context} nonce by number`);
    const params = toCommitmentNumberParamsWire(commitmentNumber);
    return context === "COMMITMENT" ? { method: "get_commitment_pub_nonce", params } : { method: "get_revocation_pub_nonce", params };
}

// Fiber's `derive_temp_channel_id_from_tlc_key`: the TLC base point followed by 33 zero bytes, CKB-hashed.
function tempChannelId(tlcBasePubkey: Uint8Array): string {
    return wireHex(bytesToHex(ckbBlake2b(tlcBasePubkey, new Uint8Array(33))));
}

function deviceFrame(frame: unknown): DeviceFrame {
    if (typeof frame !== "object" || frame === null || typeof (frame as { type?: unknown }).type !== "string") {
        throw new Error(`the device sent something that is not a frame: ${JSON.stringify(frame)}`);
    }
    return frame as DeviceFrame;
}

function stringField(frame: DeviceFrame, key: string): string {
    const value = frame[key];
    if (typeof value !== "string") throw new Error(`the device's ${frame.type} frame carries no ${key}`);
    return value;
}

function hexField(frame: DeviceFrame, key: string): Uint8Array {
    const value = stringField(frame, key);
    if (!value.startsWith("0x")) throw new Error(`the device's ${frame.type} frame writes ${key} without the 0x prefix`);
    return hexToBytes(value.slice(2));
}

function resultBytes(result: SignResultWire, key: string): Uint8Array {
    const value = (result as Record<string, unknown>)[key];
    if (typeof value !== "string" || !value.startsWith("0x")) throw new Error(`the device's result carries no hex ${key}`);
    return hexToBytes(value.slice(2));
}
