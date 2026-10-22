import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Session } from "@scure/btc-signer/musig2.js";
import type { OutPoint, Script, ScriptTemplate, TlcDirection, TlcHashAlgorithm } from "../../src/common";
import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    PARTIAL_SIGNATURE_LENGTH,
    PUBLIC_NONCE_LENGTH,
    UINT128_MAX,
    UINT64_MAX,
    ckbBlake2b,
    compareBytes,
} from "../../src/common";
import type { FiberChannelKeys } from "../../src/derivation";
import { MAX_COMMITMENT_NUMBER, derivePublicKey, getCommitmentPoint, pubkeyOf } from "../../src/derivation";
import type { CommitmentLockLayout, CommitmentTxInput, RevocationInput } from "../../src/digest";
import { REVOCATION_LOCK_ARGS_LENGTH, calculateShutdownTxFee, computeRevocationContentMessage, computeTxMessage } from "../../src/digest";
import { buildCommitmentTx } from "../../src/digest/commitment-tx";
import { buildRevocationContent } from "../../src/digest/revocation";
import { buildClosingTx } from "../../src/digest/shutdown-tx";
import { moleculeCellOutput } from "../../src/digest/utils/molecule.utils";
import type { SignSlot } from "../../src/policy";
import type { ChannelSigningTransition } from "../../src/protocol";
import type {
    ChannelSigningStatusWire,
    SignableContentWire,
    SigningSettlementTlcWire,
    SigningSettlementWire,
} from "../../src/protocol/protocol.types";
import type {
    ChannelOpenSignerMaterial,
    FetchInit,
    FetchResponseLike,
    IFetchLike,
    NextChannelSignerMaterialWire,
    RpcChannelIdParamsWire,
    RpcSubmissionResult,
    SubmitChannelSignatureParamsWire,
} from "../../src/rpc";
import { RPC_CALL_FAILED_CODE } from "../../src/rpc";
import type { TlcHashAlgorithmWire, WireField } from "../../src/wire";
import {
    WireError,
    decodeAnyHexBytes,
    decodeBareHexBytes,
    decodeHexBytes,
    encodeAnyHexBytes,
    encodeBareHexBytes,
    encodeHexBytes,
    encodeTransaction,
    encodeUintHex,
    encodeUintHexNumber,
    readObject,
    requireHexBytes,
} from "../../src/wire";
import type { SentCall } from "../mocks/rpc";
import { toLockLayout, toOutPoint, toScript } from "./digest-inputs";
import { signPeerHalf } from "./peer-musig";
import { signingCommitmentLock } from "./signing-channel";
import type { SigningVectors } from "./signing-vectors";
import { HASH_ALGORITHM_WIRE } from "./wire-spellings";

// jsonrpsee's refusals, before any fiber handler.
const METHOD_NOT_FOUND_CODE = -32601;
const INVALID_PARAMS_CODE = -32602;

// The members fiber reads as fixed-length `SliceHex`.
const FIXED_LENGTH_MEMBERS = ["channel_id", "request_id", "partial_signature"];

const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

// `ProcessingChannelError::Musig2VerifyError` around musig2's `VerifyError::BadSignature`, as `channel.rs:2271` wraps it.
const INVALID_SIGNATURE = "Invalid parameter: signature is invalid: Musig2 VerifyError: failed to verify signature: signature is invalid";

// Fiber's `requires_next_signer_material` (`fiber-types/src/channel_signer.rs:380-388`).
const ADVANCING_TRANSITIONS: readonly NodeTransition[] = [
    "SendCommitmentSigned",
    "CompleteReceivedCommitment",
    "SendRevokeAndAck",
    "CompleteReceivedRevokeAndAck",
];

// The initiator's commitment_signed, the other side's revoke_and_ack, then the reverse.
const ROUNDS = {
    tenant: ["SendCommitmentSigned", "CompleteReceivedRevokeAndAck", "CompleteReceivedCommitment", "SendRevokeAndAck"],
    peer: ["CompleteReceivedCommitment", "SendRevokeAndAck", "SendCommitmentSigned", "CompleteReceivedRevokeAndAck"],
} as const satisfies Record<string, readonly NodeTransition[]>;

type NodeTransition = Exclude<ChannelSigningTransition, "SignChannelAnnouncement">;

type NoncePurpose = "Commitment" | "Revocation";

type NodeSlot = { purpose: NoncePurpose; commitmentNumber: number };

type NodeTlc = {
    id: number;
    direction: TlcDirection;
    hashAlgorithm: TlcHashAlgorithm;
    amountShannons: bigint;
    paymentHash: Uint8Array;
    expiryMs: bigint;
    // Fiber's `created_at` (`channel.rs:9046`, `:9075`): the counters when the TLC was added.
    createdAt: { local: number; remote: number };
};

// Each side's liquid amount, TLCs aside.
type CommitmentState = { localShannons: bigint; remoteShannons: bigint; tlcs: NodeTlc[] };

type Step = { kind: "request"; transition: NodeTransition; state: CommitmentState } | { kind: "event"; run: () => void };

type PendingRequest = {
    requestId: string;
    transition: NodeTransition;
    slot: NodeSlot;
    keyAggregation: [Uint8Array, Uint8Array];
    aggNonce: Uint8Array;
    peerPublicNonce: Uint8Array;
    message: Uint8Array;
    status: ChannelSigningStatusWire;
    served: TenantNodeServed;
};

type NextMaterial = { point: Uint8Array | null; commitmentNonce: Uint8Array | null; revocationNonce: Uint8Array | null };

type Submission = { channelId: string; requestId: string; partialSignature: Uint8Array; nextMaterial: NextMaterial | null };

type RpcAnswer = { result: unknown } | { error: { code: number; message: string; data?: string } };

export type TenantNodeChannel = {
    channelId: string;
    fundingOutPoint: OutPoint;
    commitmentLock: ScriptTemplate;
    fundingLockCellDepsCount: number;
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    // At the open, reserves aside.
    localShannons: bigint;
    remoteShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
    localCloseScript: Script;
    remoteCloseScript: Script;
    localShutdownFeeRate: bigint;
    remoteShutdownFeeRate: bigint;
    lockLayout: CommitmentLockLayout;
};

export type TenantNodePayment = { paymentHash: string; amountShannons: string; hashAlgorithm: TlcHashAlgorithm; expiryMs: string };

export type TenantNodeTamper =
    // Aggregates the device's nonce of another slot.
    | { kind: "aggNonce" }
    // The peer signs another message; received transitions only.
    | { kind: "peerSignature" }
    // The settlement states another device amount, reserve included; commitments only.
    | { kind: "settlement"; localAmountShannons: string }
    // A whole commitment under another delay than the pinned one; commitments only.
    | { kind: "delayEpoch"; commitmentDelayEpoch: string }
    // Pays the device's side to another script; the close only.
    | { kind: "closeScript"; script: Script };

export type TenantNodeServed = {
    requestId: string;
    transition: NodeTransition;
    // `<purpose>@<number>`, fiber's `NonceSlot`.
    slot: string;
    // Lowercase hex.
    message: string;
    answers: RpcSubmissionResult[];
};

export type TenantNodeOptions = {
    channel: TenantNodeChannel;
    // A test shortcut: the node holds only the public parts, but the SDK's builders take the secrets.
    deviceKeys: FiberChannelKeys;
    peerKeys: FiberChannelKeys;
};

export function tenantNodeChannelOf(vectors: SigningVectors): TenantNodeChannel {
    const { channel } = vectors;
    return {
        channelId: channel.channel_id,
        fundingOutPoint: toOutPoint(channel.funding_out_point),
        commitmentLock: signingCommitmentLock(vectors),
        fundingLockCellDepsCount: channel.funding_lock_cell_deps_count,
        commitmentDelayEpoch: BigInt(channel.delay_epoch),
        commitmentFeeRate: BigInt(channel.commitment_fee_rate),
        localShannons: BigInt(channel.to_local),
        remoteShannons: BigInt(channel.to_remote),
        localReservedCkbShannons: BigInt(channel.local_reserved),
        remoteReservedCkbShannons: BigInt(channel.remote_reserved),
        localCloseScript: toScript(channel.local_close_script),
        remoteCloseScript: toScript(channel.remote_close_script),
        localShutdownFeeRate: BigInt(channel.local_shutdown_fee_rate),
        remoteShutdownFeeRate: BigInt(channel.remote_shutdown_fee_rate),
        lockLayout: toLockLayout(channel.lock_layout),
    };
}

export class InMemoryTenantNode {
    readonly fetch: IFetchLike;

    private readonly channel: TenantNodeChannel;

    private readonly deviceKeys: FiberChannelKeys;

    private readonly peerKeys: FiberChannelKeys;

    private readonly sent: SentCall[] = [];

    private readonly log: TenantNodeServed[] = [];

    // Fiber's `CommitmentNumbers`, starting at 0 (`fiber-types/src/channel.rs:328`).
    private local = 0;

    private remote = 0;

    private material: ChannelOpenSignerMaterial | null = null;

    // Fiber's `local_commitment_points` and `local_public_nonces`: only what the device published.
    private readonly points = new Map<number, Uint8Array>();

    private readonly nonces = new Map<string, Uint8Array>();

    private localShannons: bigint;

    private remoteShannons: bigint;

    private tlcs: NodeTlc[] = [];

    private nextTlcIds: Record<TlcDirection, number> = { offered: 0, received: 0 };

    // The peer messages fiber buffers behind the request in flight (`channel.rs:6239`), drained once it completes (`:2195`).
    private readonly queue: Step[] = [];

    private pending: PendingRequest | null = null;

    private lastApplied: { requestId: string; receipt: string; served: TenantNodeServed } | null = null;

    private readonly tampers: TenantNodeTamper[] = [];

    private readonly skips: NodeTransition[] = [];

    private forgetSecondSession: ((slot: SignSlot) => Promise<void>) | null = null;

    private parkNext = false;

    private readonly parked: unknown[] = [];

    constructor(options: TenantNodeOptions) {
        this.channel = options.channel;
        this.deviceKeys = options.deviceKeys;
        this.peerKeys = options.peerKeys;
        this.localShannons = options.channel.localShannons;
        this.remoteShannons = options.channel.remoteShannons;
        this.fetch = async (_url: string, init: FetchInit): Promise<FetchResponseLike> => {
            const request = JSON.parse(init.body) as { id: number; method: string; params: unknown[] };
            const params = request.params[0];
            this.sent.push({ method: request.method, params });
            if (request.method === "submit_channel_signature" && this.parkNext) {
                this.parkNext = false;
                this.parked.push(params);
                // Its sender is gone: the answer reaches no one.
                return new Promise<FetchResponseLike>(() => undefined);
            }
            if (request.method === "get_channel_signing_status") await this.beforeThirdSession();
            const body = JSON.stringify({ jsonrpc: "2.0", id: request.id, ...this.answer(request.method, params) });
            return { status: 200, text: () => Promise.resolve(body) };
        };
    }

    get calls(): SentCall[] {
        return structuredClone(this.sent);
    }

    get served(): TenantNodeServed[] {
        return structuredClone(this.log);
    }

    get counters(): { local: number; remote: number } {
        return { local: this.local, remote: this.remote };
    }

    get published(): { nonces: string[]; points: number[] } {
        return { nonces: [...this.nonces.keys()].sort(), points: [...this.points.keys()].sort((a, b) => a - b) };
    }

    openTenantChannel(material: ChannelOpenSignerMaterial, first: "CompleteReceivedCommitment" | "SendCommitmentSigned"): string {
        if (this.material !== null) throw new Error("the node already opened its channel");
        this.material = material;
        // Installed as fiber's `apply_open_signer_material` does (`channel.rs:5958-6005`); a tenant channel has no announcement.
        this.points.set(1, material.firstCommitmentPoint);
        this.points.set(2, material.secondCommitmentPoint);
        this.nonces.set(slotKey({ purpose: "Commitment", commitmentNumber: 0 }), material.commitmentNonce);
        this.nonces.set(slotKey({ purpose: "Commitment", commitmentNumber: 1 }), material.nextCommitmentNonce);
        this.nonces.set(slotKey({ purpose: "Revocation", commitmentNumber: 2 }), material.revocationNonce);
        // R+1 at TxComplete (`channel.rs:9545`), L+1 entering the wait for the external funding (`:4161`).
        this.remote += 1;
        this.local += 1;
        const state = this.state();
        const second = first === "SendCommitmentSigned" ? "CompleteReceivedCommitment" : "SendCommitmentSigned";
        this.queue.push(
            { kind: "request", transition: first, state },
            { kind: "request", transition: second, state },
            {
                kind: "event",
                // ChannelReady moves both (`channel.rs:9905`).
                run: () => {
                    this.local += 1;
                    this.remote += 1;
                },
            },
        );
        this.drain();
        return this.channel.channelId;
    }

    sendPayment(payment: TenantNodePayment): void {
        const tlc = this.addTlc("offered", payment);
        this.localShannons -= tlc.amountShannons;
        this.round("tenant");
    }

    receivePayment(payment: TenantNodePayment): void {
        const tlc = this.addTlc("received", payment);
        this.remoteShannons -= tlc.amountShannons;
        this.round("peer");
    }

    // The side the TLC pays fulfils it: the peer an offered one, the tenant's node a received one.
    fulfil(paymentHash: string): void {
        const tlc = this.tlcs.find((candidate) => bytesToHex(candidate.paymentHash) === paymentHash);
        if (tlc === undefined) throw new Error(`no TLC under ${paymentHash} is in flight`);
        this.tlcs = this.tlcs.filter((candidate) => candidate !== tlc);
        if (tlc.direction === "offered") {
            this.remoteShannons += tlc.amountShannons;
            this.round("peer");
        } else {
            this.localShannons += tlc.amountShannons;
            this.round("tenant");
        }
    }

    shutdown(): void {
        if (this.tlcs.length > 0) throw new Error("a channel with TLCs in flight does not shut down");
        this.queue.push({ kind: "request", transition: "SendClosingSigned", state: this.state() });
        this.drain();
    }

    tamperNext(tamper: TenantNodeTamper): void {
        this.tampers.push(tamper);
    }

    // Skips the transition's next request as if answered: a step no fiber node takes.
    skipNext(transition: NodeTransition): void {
        this.skips.push(transition);
    }

    // Skips the request in flight as if answered: no fiber node does.
    skipPending(): void {
        const pending = this.pending;
        if (pending === null) throw new Error("no request is in flight");
        this.pending = null;
        this.advance(pending.transition);
        this.drain();
    }

    // Test-only opt-in past Fiber's nonce stall: before the device reads a slot's third session, the flow forgets its second.
    bypassNonceCap(forgetSecondSession: (slot: SignSlot) => Promise<void>): void {
        this.forgetSecondSession = forgetSecondSession;
    }

    // The next submission lands just before the one after it, and its answer reaches no one.
    parkNextSubmission(): void {
        this.parkNext = true;
    }

    private async beforeThirdSession(): Promise<void> {
        const pending = this.pending;
        if (this.forgetSecondSession === null || pending === null) return;
        const slot = slotKey(pending.slot);
        const applied = this.log.filter((request) => request.slot === slot && request.answers.includes("Applied")).length;
        if (applied < 2) return;
        await this.forgetSecondSession(
            `${pending.slot.purpose === "Commitment" ? "COMMITMENT" : "REVOKE"}:${pending.slot.commitmentNumber}`,
        );
    }

    private answer(method: string, params: unknown): RpcAnswer {
        switch (method) {
            case "list_channels":
                return { result: { channels: this.material === null ? [] : [{ channel_id: this.channel.channelId }] } };
            case "get_channel_signing_status":
                return this.signingStatus(params);
            case "submit_channel_signature":
                for (const parked of this.parked.splice(0)) this.submit(parked);
                return this.submit(params);
            default:
                return { error: { code: METHOD_NOT_FOUND_CODE, message: "Method not found" } };
        }
    }

    private signingStatus(params: unknown): RpcAnswer {
        const channelId = readParams<RpcChannelIdParamsWire, string>(params, (at) => requireHexBytes(at("channel_id"), HASH256_LENGTH));
        if (channelId instanceof WireError) return invalidParams(params, channelId);
        // `rpc/channel.rs:824-826`, the id in fiber's `Hash256` debug form.
        if (!this.isChannel(channelId)) return failed(`channel Hash256(${channelId}) not found`);
        const status: ChannelSigningStatusWire = this.pending?.status ?? { type: "NoSignatureRequired" };
        return { result: { channel_id: channelId, status: structuredClone(status) } };
    }

    // Fiber's `validate_and_checkpoint_signer_notification` and its continuation (`channel.rs:2208-2285`).
    private submit(params: unknown): RpcAnswer {
        const submission = readParams<SubmitChannelSignatureParamsWire, Submission>(params, readSubmission);
        if (submission instanceof WireError) return invalidParams(params, submission);
        // Converted before the network actor sees them (`rpc/channel.rs:840-847`): musig2's scalar, then each nonce.
        if (bytesToNumberBE(submission.partialSignature) >= CURVE_ORDER) return failed("received invalid scalar bytes");
        const material = submission.nextMaterial;
        for (const nonce of material === null ? [] : [material.commitmentNonce, material.revocationNonce]) {
            if (nonce !== null && nonce.length !== PUBLIC_NONCE_LENGTH) {
                return failed(`error decoding musig2::nonces::PubNonce: unexpected length ${nonce.length}`);
            }
        }
        // The network actor's lookup (`network.rs:3325-3327`).
        if (!this.isChannel(submission.channelId)) return failed(`channel Hash256(${submission.channelId}) not found`);
        const receipt = receiptOf(submission);
        // `replay_or_pending` (`fiber-types/src/channel_signer.rs:542-560`); a request never outlives its apply here.
        if (this.lastApplied !== null) {
            if (this.lastApplied.receipt === receipt) {
                this.lastApplied.served.answers.push("AlreadyApplied");
                return { result: { type: "AlreadyApplied" } };
            }
            if (this.lastApplied.requestId === submission.requestId) {
                return failed("Invalid state: submitted signature does not match the previously applied result");
            }
        }
        const pending = this.pending;
        if (pending === null) return failed("Invalid state: channel is not waiting for a signature");
        if (pending.requestId !== submission.requestId) {
            return failed("Invalid state: signature request id does not match the current request");
        }
        // Against the nonce the device published for the slot (`channel.rs:6167-6206`).
        if (!this.verifiesDeviceHalf(pending, submission.partialSignature)) return failed(INVALID_SIGNATURE);
        const refusal = this.installNextMaterial(pending, submission.nextMaterial);
        if (refusal !== null) return failed(refusal);
        this.lastApplied = { requestId: submission.requestId, receipt, served: pending.served };
        pending.served.answers.push("Applied");
        this.pending = null;
        this.advance(pending.transition);
        this.drain();
        return { result: { type: "Applied" } };
    }

    private verifiesDeviceHalf(pending: PendingRequest, partialSignature: Uint8Array): boolean {
        const deviceNonce = this.publishedNonce(pending.slot);
        const deviceIndex = equalBytes(pending.keyAggregation[0], this.openMaterial().fundingPubkey) ? 0 : 1;
        const nonces = deviceIndex === 0 ? [deviceNonce, pending.peerPublicNonce] : [pending.peerPublicNonce, deviceNonce];
        return new Session(pending.aggNonce, pending.keyAggregation, pending.message).partialSigVerify(
            partialSignature,
            nonces,
            deviceIndex,
        );
    }

    // Fiber's `apply_next_signer_material` (`channel.rs:6009-6139`): checked whole, then installed at the slot's number plus one.
    private installNextMaterial(pending: PendingRequest, material: NextMaterial | null): string | null {
        const required = ADVANCING_TRANSITIONS.includes(pending.transition);
        if (material === null) {
            return required ? `Invalid parameter: channel signer must provide next_material for transition ${pending.transition}` : null;
        }
        const number = pending.slot.commitmentNumber + 1;
        if (required) {
            if (material.point === null) {
                return `Invalid parameter: channel signer next_material missing next_commitment_point for commitment ${number}`;
            }
            if (material.commitmentNonce === null) {
                return `Invalid parameter: channel signer next_material missing next_commitment_nonce for commitment ${number}`;
            }
            if (material.revocationNonce === null) {
                return `Invalid parameter: channel signer next_material missing next_revocation_nonce for commitment ${number}`;
            }
        }
        if (
            material.commitmentNonce !== null &&
            material.revocationNonce !== null &&
            equalBytes(material.commitmentNonce, material.revocationNonce)
        ) {
            return "Invalid parameter: channel signer commitment and revocation nonces must be distinct";
        }
        const point = this.points.get(number);
        if (material.point !== null && point !== undefined && !equalBytes(point, material.point)) {
            return `Invalid parameter: channel signer commitment point ${number} conflicts with persisted material`;
        }
        const submitted: [NodeSlot, Uint8Array | null][] = [
            [{ purpose: "Commitment", commitmentNumber: number }, material.commitmentNonce],
            [{ purpose: "Revocation", commitmentNumber: number }, material.revocationNonce],
        ];
        for (const [slot, nonce] of submitted) {
            const installed = this.nonces.get(slotKey(slot));
            if (nonce !== null && installed !== undefined && !equalBytes(installed, nonce)) {
                return `Invalid parameter: channel signer nonce NonceSlot { purpose: ${slot.purpose}, commitment_number: ${number} } conflicts with persisted material`;
            }
        }
        if (material.point !== null) this.points.set(number, material.point);
        for (const [slot, nonce] of submitted) if (nonce !== null) this.nonces.set(slotKey(slot), nonce);
        return null;
    }

    // A commitment_signed never moves L.
    private advance(transition: NodeTransition): void {
        // `finish_send_revoke_and_ack` (`channel.rs:6313`) and `finish_received_revoke_and_ack` (`:6462`).
        if (transition === "SendRevokeAndAck") this.remote += 1;
        if (transition === "CompleteReceivedRevokeAndAck") this.local += 1;
    }

    // One request at a time (`fiber-types/src/channel_signer.rs:508-520`).
    private drain(): void {
        while (this.pending === null) {
            const step = this.queue.shift();
            if (step === undefined) return;
            if (step.kind === "event") {
                step.run();
                continue;
            }
            const skip = this.skips.indexOf(step.transition);
            if (skip >= 0) {
                this.skips.splice(skip, 1);
                this.advance(step.transition);
                continue;
            }
            this.pending = this.issue(step.transition, step.state);
        }
    }

    private issue(transition: NodeTransition, state: CommitmentState): PendingRequest {
        const index = this.log.length;
        const requestId = encodeHexBytes("requestId", ckbBlake2b(utf8ToBytes(`tenant node request ${index}`)), HASH256_LENGTH);
        const tamper = this.takeTamper(transition);
        const slot = this.slotOf(transition);
        const keyAggregation = this.keyAggregationOf(transition);
        const built = this.contentOf(transition, slot, state, tamper);
        const devicePublicNonce =
            tamper?.kind === "aggNonce" ? this.publishedNonce({ purpose: "Commitment", commitmentNumber: 0 }) : this.publishedNonce(slot);
        const signed = tamper?.kind === "peerSignature" ? ckbBlake2b(built.message) : built.message;
        // A fresh peer nonce per request, as fiber's peer draws one per session.
        const half = signPeerHalf(this.peerKeys.fundingKey, { keyAggregation, devicePublicNonce, message: signed }, (index % 250) + 1);
        const received = transition === "CompleteReceivedCommitment" || transition === "CompleteReceivedRevokeAndAck";
        const served: TenantNodeServed = {
            requestId,
            transition,
            slot: slotKey(slot),
            message: bytesToHex(built.message),
            answers: [],
        };
        this.log.push(served);
        const status: ChannelSigningStatusWire = {
            type: "SignatureRequired",
            request_id: requestId,
            transition,
            content: {
                slot: {
                    purpose: slot.purpose,
                    commitment_number: encodeUintHexNumber("slot", slot.commitmentNumber, MAX_COMMITMENT_NUMBER),
                },
                commitment_counter: transition === "SendRevokeAndAck" ? "Remote" : "Local",
                key_agg_ctx: encodeAnyHexBytes("keyAggCtx", keyAggContextOf(keyAggregation)),
                agg_nonce: encodeHexBytes("aggNonce", half.aggNonce, PUBLIC_NONCE_LENGTH),
                content: built.content,
            },
            session_evidence: {
                peer_public_nonce: encodeHexBytes("peerPublicNonce", half.peerPublicNonce, PUBLIC_NONCE_LENGTH),
                peer_partial_signature: received
                    ? encodeHexBytes("peerPartialSignature", half.peerPartialSignature, PARTIAL_SIGNATURE_LENGTH)
                    : null,
            },
            settlement: built.settlement,
        };
        return {
            requestId,
            transition,
            slot,
            keyAggregation,
            aggNonce: half.aggNonce,
            peerPublicNonce: half.peerPublicNonce,
            message: built.message,
            status,
            served,
        };
    }

    private takeTamper(transition: NodeTransition): TenantNodeTamper | null {
        const index = this.tampers.findIndex((tamper) => tamperApplies(tamper, transition));
        if (index < 0) return null;
        const [tamper] = this.tampers.splice(index, 1);
        return tamper ?? null;
    }

    // The request sites: `channel.rs:6209`, `:9704`, `:8007`, `:10202`, `:9200`.
    private slotOf(transition: NodeTransition): NodeSlot {
        switch (transition) {
            case "SendRevokeAndAck":
                return { purpose: "Revocation", commitmentNumber: this.remote };
            case "CompleteReceivedRevokeAndAck":
                return { purpose: "Revocation", commitmentNumber: this.local };
            case "SendCommitmentSigned":
            case "CompleteReceivedCommitment":
            case "SendClosingSigned":
                return { purpose: "Commitment", commitmentNumber: this.local };
        }
    }

    // `order_things_for_musig2` for a funding spend (`channel.rs:11028-11042`); a revocation keeps its lock's role order (`:11120-11129`).
    private keyAggregationOf(transition: NodeTransition): [Uint8Array, Uint8Array] {
        const device = this.openMaterial().fundingPubkey;
        const peer = pubkeyOf(this.peerKeys.fundingKey);
        if (transition === "SendRevokeAndAck") return [peer, device];
        if (transition === "CompleteReceivedRevokeAndAck") return [device, peer];
        return compareBytes(device, peer) <= 0 ? [device, peer] : [peer, device];
    }

    private contentOf(
        transition: NodeTransition,
        slot: NodeSlot,
        state: CommitmentState,
        tamper: TenantNodeTamper | null,
    ): { content: SignableContentWire; message: Uint8Array; settlement: SigningSettlementWire | null } {
        switch (transition) {
            // The tx's version is L for the peer's commitment, R for the device's own (`channel.rs:11349`).
            case "SendCommitmentSigned":
                return this.commitmentContent(state, true, this.local, tamper);
            case "CompleteReceivedCommitment":
                return this.commitmentContent(state, false, this.remote, tamper);
            // Each revokes the version below its slot's (`channel.rs:7987`, `:10182`).
            case "SendRevokeAndAck":
                return this.revocationContent(false, slot.commitmentNumber - 1);
            case "CompleteReceivedRevokeAndAck":
                return this.revocationContent(true, slot.commitmentNumber - 1);
            case "SendClosingSigned":
                return this.closingContent(state, tamper);
        }
    }

    private commitmentContent(
        state: CommitmentState,
        forRemote: boolean,
        version: number,
        tamper: TenantNodeTamper | null,
    ): { content: SignableContentWire; message: Uint8Array; settlement: SigningSettlementWire } {
        const { channel } = this;
        const input: CommitmentTxInput = {
            ...this.commitmentTerms(),
            forRemote,
            fundingOutPoint: channel.fundingOutPoint,
            remoteTlcBasePubkey: pubkeyOf(this.peerKeys.tlcBaseKey),
            commitmentNumber: version,
            commitmentDelayEpoch: tamper?.kind === "delayEpoch" ? BigInt(tamper.commitmentDelayEpoch) : channel.commitmentDelayEpoch,
            settlementLocalShannons: state.localShannons,
            settlementRemoteShannons: state.remoteShannons,
            tlcs: state.tlcs.map((tlc) => ({
                id: tlc.id,
                direction: tlc.direction,
                hashAlgorithm: tlc.hashAlgorithm,
                amountShannons: tlc.amountShannons,
                paymentHash: tlc.paymentHash,
                expiryMs: tlc.expiryMs,
                localKeyCommitmentNumber: tlc.createdAt.remote,
                remoteTlcPubkey: this.peerTlcPubkey(tlc),
            })),
        };
        const transaction = buildCommitmentTx(this.deviceKeys, input);
        const localAmount =
            tamper?.kind === "settlement" ? BigInt(tamper.localAmountShannons) : state.localShannons + channel.localReservedCkbShannons;
        const settlement: SigningSettlementWire = {
            local_amount: encodeUintHex("localAmount", localAmount, UINT128_MAX),
            remote_amount: encodeUintHex("remoteAmount", state.remoteShannons + channel.remoteReservedCkbShannons, UINT128_MAX),
            local_settlement_pubkey: encodeBareHexBytes("localSettlementPubkey", this.openMaterial().tlcBaseKey, COMPRESSED_POINT_LENGTH),
            remote_settlement_pubkey: encodeBareHexBytes(
                "remoteSettlementPubkey",
                pubkeyOf(this.peerKeys.tlcBaseKey),
                COMPRESSED_POINT_LENGTH,
            ),
            for_remote: forRemote,
            tlcs: state.tlcs.map((tlc) => this.settlementTlc(tlc)),
        };
        return {
            content: { type: "CommitmentTransaction", transaction: encodeTransaction("transaction", transaction) },
            message: computeTxMessage(transaction),
            settlement,
        };
    }

    // Fiber's `get_tlc_keys` for an external signer (`channel.rs:8588-8615`): each key from its side's published point.
    private settlementTlc(tlc: NodeTlc): SigningSettlementTlcWire {
        const localKeyPubkey = derivePublicKey(this.openMaterial().tlcBaseKey, this.publishedPoint(tlc.createdAt.remote));
        return {
            tlc_id: encodeUintHexNumber("tlcId", tlc.id, Number.MAX_SAFE_INTEGER),
            local_key_commitment_number: encodeUintHexNumber("localKeyCommitmentNumber", tlc.createdAt.remote, MAX_COMMITMENT_NUMBER),
            inbound: tlc.direction === "received",
            payment_hash: encodeHexBytes("paymentHash", tlc.paymentHash, HASH256_LENGTH),
            payment_amount: encodeUintHex("paymentAmount", tlc.amountShannons, UINT128_MAX),
            hash_algorithm: hashAlgorithmWire(tlc.hashAlgorithm),
            expiry: encodeUintHex("expiry", tlc.expiryMs, UINT64_MAX),
            local_key_pubkey: encodeBareHexBytes("localKeyPubkey", localKeyPubkey, COMPRESSED_POINT_LENGTH),
            remote_key: encodeBareHexBytes("remoteKey", this.peerTlcPubkey(tlc), COMPRESSED_POINT_LENGTH),
        };
    }

    private peerTlcPubkey(tlc: NodeTlc): Uint8Array {
        return derivePublicKey(pubkeyOf(this.peerKeys.tlcBaseKey), getCommitmentPoint(this.peerKeys.commitmentSeed, tlc.createdAt.local));
    }

    private revocationContent(
        forRemote: boolean,
        revokedCommitmentNumber: number,
    ): { content: SignableContentWire; message: Uint8Array; settlement: null } {
        const input: RevocationInput = {
            ...this.commitmentTerms(),
            forRemote,
            revokedCommitmentNumber,
            // Sending revokes the device's commitment to the peer's benefit; receiving, the peer's to the device's.
            payoutScript: forRemote ? this.channel.localCloseScript : this.channel.remoteCloseScript,
            commitmentDelayEpoch: this.channel.commitmentDelayEpoch,
        };
        const { output, outputData, commitmentLockArgs } = buildRevocationContent(this.deviceKeys, input);
        return {
            content: {
                type: "Revocation",
                output: encodeAnyHexBytes("output", moleculeCellOutput(output.capacityShannons, output.lock, output.type)),
                output_data: encodeAnyHexBytes("outputData", outputData),
                commitment_lock_script_args: encodeHexBytes("commitmentLockArgs", commitmentLockArgs, REVOCATION_LOCK_ARGS_LENGTH),
            },
            message: computeRevocationContentMessage(output, outputData, commitmentLockArgs),
            settlement: null,
        };
    }

    // Fiber's `build_shutdown_tx`: each side's total less its own fee.
    private closingContent(
        state: CommitmentState,
        tamper: TenantNodeTamper | null,
    ): { content: SignableContentWire; message: Uint8Array; settlement: null } {
        const { channel } = this;
        const localCloseScript = tamper?.kind === "closeScript" ? tamper.script : channel.localCloseScript;
        const sizing = {
            cellDepsCount: channel.fundingLockCellDepsCount,
            udtTypeScript: null,
            localCloseScript,
            remoteCloseScript: channel.remoteCloseScript,
        };
        const transaction = buildClosingTx(
            this.deviceKeys,
            {
                fundingOutPoint: channel.fundingOutPoint,
                remoteFundingPubkey: pubkeyOf(this.peerKeys.fundingKey),
                localCloseScript,
                remoteCloseScript: channel.remoteCloseScript,
                localCapacityShannons:
                    state.localShannons + channel.localReservedCkbShannons - calculateShutdownTxFee(channel.localShutdownFeeRate, sizing),
                remoteCapacityShannons:
                    state.remoteShannons +
                    channel.remoteReservedCkbShannons -
                    calculateShutdownTxFee(channel.remoteShutdownFeeRate, sizing),
            },
            null,
        );
        return {
            content: { type: "CooperativeCloseTransaction", transaction: encodeTransaction("transaction", transaction) },
            message: computeTxMessage(transaction),
            settlement: null,
        };
    }

    private commitmentTerms() {
        const { channel } = this;
        return {
            remoteFundingPubkey: pubkeyOf(this.peerKeys.fundingKey),
            commitmentFeeRate: channel.commitmentFeeRate,
            cellDepsCount: channel.fundingLockCellDepsCount,
            udtTypeScript: null,
            liquidCapacityShannons: channel.localShannons + channel.remoteShannons,
            localReservedCkbShannons: channel.localReservedCkbShannons,
            remoteReservedCkbShannons: channel.remoteReservedCkbShannons,
            commitmentLock: channel.commitmentLock,
            lockLayout: channel.lockLayout,
        };
    }

    private addTlc(direction: TlcDirection, payment: TenantNodePayment): NodeTlc {
        const tlc: NodeTlc = {
            id: this.nextTlcIds[direction],
            direction,
            hashAlgorithm: payment.hashAlgorithm,
            amountShannons: BigInt(payment.amountShannons),
            paymentHash: hexToBytes(payment.paymentHash),
            expiryMs: BigInt(payment.expiryMs),
            createdAt: { local: this.local, remote: this.remote },
        };
        this.nextTlcIds = { ...this.nextTlcIds, [direction]: tlc.id + 1 };
        this.tlcs = [...this.tlcs, tlc];
        return tlc;
    }

    private round(initiator: keyof typeof ROUNDS): void {
        const state = this.state();
        this.queue.push(...ROUNDS[initiator].map((transition): Step => ({ kind: "request", transition, state })));
        this.drain();
    }

    private state(): CommitmentState {
        return { localShannons: this.localShannons, remoteShannons: this.remoteShannons, tlcs: [...this.tlcs] };
    }

    private isChannel(channelId: string): boolean {
        return this.material !== null && channelId === this.channel.channelId;
    }

    private openMaterial(): ChannelOpenSignerMaterial {
        if (this.material === null) throw new Error("the node has opened no channel");
        return this.material;
    }

    // A slot the device never published is a broken flow, not an answer.
    private publishedNonce(slot: NodeSlot): Uint8Array {
        const nonce = this.nonces.get(slotKey(slot));
        if (nonce === undefined) throw new Error(`the device published no nonce for ${slotKey(slot)}`);
        return nonce;
    }

    private publishedPoint(commitmentNumber: number): Uint8Array {
        const point = this.points.get(commitmentNumber);
        if (point === undefined) throw new Error(`the device published no commitment point ${commitmentNumber}`);
        return point;
    }
}

function tamperApplies(tamper: TenantNodeTamper, transition: NodeTransition): boolean {
    switch (tamper.kind) {
        case "aggNonce":
            return true;
        case "peerSignature":
            return transition === "CompleteReceivedCommitment" || transition === "CompleteReceivedRevokeAndAck";
        case "settlement":
        case "delayEpoch":
            return transition === "SendCommitmentSigned" || transition === "CompleteReceivedCommitment";
        case "closeScript":
            return transition === "SendClosingSigned";
    }
}

function hashAlgorithmWire(algorithm: TlcHashAlgorithm): TlcHashAlgorithmWire {
    const spelling = HASH_ALGORITHM_WIRE[algorithm];
    if (spelling === undefined) throw new Error(`no wire spelling for ${algorithm}`);
    return spelling;
}

function slotKey(slot: NodeSlot): string {
    return `${slot.purpose}@${slot.commitmentNumber}`;
}

// musig2's `KeyAggContext::to_bytes` of two untweaked keys: header, big-endian count, the keys in aggregation order.
function keyAggContextOf(keys: [Uint8Array, Uint8Array]): Uint8Array {
    return concatBytes(Uint8Array.of(0x00, 0x00, 0x00, 0x00, keys.length), ...keys);
}

function failed(message: string): RpcAnswer {
    return { error: { code: RPC_CALL_FAILED_CODE, message } };
}

function readParams<Wire extends object, Value>(
    params: unknown,
    read: (at: (name: keyof Wire & string) => WireField) => Value,
): Value | WireError {
    try {
        return read(readObject<Wire>({ value: params, path: "params" }));
    } catch (error) {
        if (error instanceof WireError) return error;
        throw error;
    }
}

function invalidParams(params: unknown, error: WireError): RpcAnswer {
    const member = error.path.startsWith("params.") ? error.path.slice("params.".length) : null;
    const value =
        member !== null && typeof params === "object" && params !== null ? (params as Record<string, unknown>)[member] : undefined;
    // serde's text for a fixed-length `SliceHex` of another length (`fiber-json-types/src/serde_utils.rs:32`); serde goes on
    // with the bytes and position, the double with the field.
    const wrongLength =
        FIXED_LENGTH_MEMBERS.some((fixed) => fixed === member) && typeof value === "string" && /^0x(?:[0-9a-f]{2})*$/.test(value);
    const data = wrongLength ? `failed to convert vector into type: ${error.message}` : error.message;
    return { error: { code: INVALID_PARAMS_CODE, message: "Invalid params", data } };
}

function readSubmission(at: (name: keyof SubmitChannelSignatureParamsWire & string) => WireField): Submission {
    const material = at("next_material");
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        requestId: requireHexBytes(at("request_id"), HASH256_LENGTH),
        partialSignature: decodeHexBytes(at("partial_signature"), PARTIAL_SIGNATURE_LENGTH),
        nextMaterial: material.value === undefined || material.value === null ? null : readNextMaterial(material),
    };
}

// Each member optional, as fiber's own type has them, so a missing one gets fiber's refusal rather than a parse error.
function readNextMaterial(field: WireField): NextMaterial {
    const at = readObject<NextChannelSignerMaterialWire>(field);
    const optional = (name: keyof NextChannelSignerMaterialWire, read: (member: WireField) => Uint8Array): Uint8Array | null => {
        const member = at(name);
        return member.value === undefined || member.value === null ? null : read(member);
    };
    return {
        point: optional("next_commitment_point", (member) => decodeBareHexBytes(member, COMPRESSED_POINT_LENGTH)),
        // `Option<SliceHex>` over a `Vec<u8>` (`fiber-json-types/src/channel.rs:912-919`): any length reads, the submit refuses.
        commitmentNonce: optional("next_commitment_nonce", decodeAnyHexBytes),
        revocationNonce: optional("next_revocation_nonce", decodeAnyHexBytes),
    };
}

// Fiber compares receipts whole: the request id, the partial signature and the material.
function receiptOf(submission: Submission): string {
    const material = submission.nextMaterial;
    const hex = (bytes: Uint8Array | null): string => (bytes === null ? "-" : bytesToHex(bytes));
    const parts = [submission.requestId, bytesToHex(submission.partialSignature)];
    if (material !== null) parts.push(hex(material.point), hex(material.commitmentNonce), hex(material.revocationNonce));
    return parts.join(":");
}
