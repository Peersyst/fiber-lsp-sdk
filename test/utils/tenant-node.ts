import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Session } from "@scure/btc-signer/musig2.js";
import type { CellDep, OutPoint, Script, ScriptTemplate, TlcDirection, TlcHashAlgorithm, Transaction } from "../../src/common";
import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    MILLISECONDS_PER_SECOND,
    PARTIAL_SIGNATURE_LENGTH,
    PUBLIC_NONCE_LENGTH,
    RECOVERABLE_ECDSA_SIGNATURE_LENGTH,
    SHANNONS_PER_CKB,
    UINT128_MAX,
    UINT64_MAX,
    blake160,
    ckbBlake2b,
    compareBytes,
} from "../../src/common";
import type { FiberChannelKeys } from "../../src/derivation";
import { MAX_COMMITMENT_NUMBER, derivePublicKey, getCommitmentPoint, pubkeyOf } from "../../src/derivation";
import type { CommitmentLockLayout, CommitmentTxInput, RevocationInput } from "../../src/digest";
import {
    FUNDING_LOCK_TESTNET,
    REVOCATION_LOCK_ARGS_LENGTH,
    buildCommitmentSettlementWitness,
    buildCommitmentTx,
    calculateShutdownTxFee,
    computeRevocationContentMessage,
    computeTxHash,
    computeTxMessage,
    fundingLockArgs,
    moleculeCellOutput,
    readCommitmentLockVersion,
    tenantChannelId,
} from "../../src/digest";
import { buildRevocationContent } from "../../src/digest/revocation";
import { buildClosingTx } from "../../src/digest/shutdown-tx";
import type { PolicyView, SignSlot, WatchtowerKeyPurpose } from "../../src/policy";
import { reservedCkbShannons } from "../../src/policy";
import type { ChannelSigningTransition } from "../../src/protocol";
import type {
    ChannelSigningStatusWire,
    OnchainKeyPurposeWire,
    SignableContentWire,
    SigningSettlementTlcWire,
    SigningSettlementWire,
    WatchtowerSigningStatusWire,
} from "../../src/protocol/protocol.types";
import type {
    ChannelOpenSignerMaterial,
    ChannelOpenSignerMaterialWire,
    FetchInit,
    FetchResponseLike,
    IFetchLike,
    ListChannelsParamsWire,
    NextChannelSignerMaterialWire,
    OpenTenantChannelParamsWire,
    OpenTenantChannelResultWire,
    RpcChannelIdParamsWire,
    RpcChannelStateWire,
    RpcChannelWire,
    RpcSubmissionResult,
    SubmitChannelSignatureParamsWire,
    SubmitSignedFundingTxParamsWire,
    SubmitWatchtowerSignatureParamsWire,
    TenantChannelOpeningContextWire,
} from "../../src/rpc";
import { RPC_CALL_FAILED_CODE } from "../../src/rpc";
import type { TlcHashAlgorithmWire, WireField } from "../../src/wire";
import {
    WireError,
    decodeAnyHexBytes,
    decodeBareHexBytes,
    decodeBoolean,
    decodeCellDep,
    decodeHexBytes,
    decodeScript,
    decodeTransaction,
    decodeUintHex,
    encodeAnyHexBytes,
    encodeBareHexBytes,
    encodeHexBytes,
    encodeScript,
    encodeTransaction,
    encodeUintHex,
    encodeUintHexNumber,
    readArray,
    readObject,
    requireHexBytes,
} from "../../src/wire";
import type { SentCall } from "../mocks/rpc";
import { toLockLayout, toOutPoint, toScript } from "./digest-inputs";
import { signPeerHalf } from "./peer-musig";
import { signingCommitmentLock } from "./signing-channel";
import type { SigningVectors } from "./signing-vectors";
import type { WatchtowerCell, WatchtowerParty, WatchtowerSpendContext, WatchtowerTlc } from "./tenant-watchtower";
import {
    SECP_PLACEHOLDER_WITNESS,
    buildWatchtowerSpend,
    pickWatchtowerUnlock,
    trackWatchtowerTlcs,
    verifyWatchtowerSignature,
    watchtowerRequestId,
} from "./tenant-watchtower";
import { HASH_ALGORITHM_WIRE } from "./wire-spellings";

// jsonrpsee's refusals, before any fiber handler.
const METHOD_NOT_FOUND_CODE = -32601;
const INVALID_PARAMS_CODE = -32602;

// The members fiber reads as fixed-length `SliceHex`.
const FIXED_LENGTH_MEMBERS = ["channel_id", "request_id", "partial_signature"];

const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

// `ProcessingChannelError::Musig2VerifyError` around musig2's `VerifyError::BadSignature`, as `channel.rs:2271` wraps it.
const INVALID_SIGNATURE = "Invalid parameter: signature is invalid: Musig2 VerifyError: failed to verify signature: signature is invalid";

// The cells the funding tx spends, which nothing resolves here: the user's, collected under the open's `funding_lock_script`, and
// the LSP's.
const USER_CELL: OutPoint = { txHash: ckbBlake2b(utf8ToBytes("tenant node user cell")), index: 0 };

const LSP_CELL: OutPoint = { txHash: ckbBlake2b(utf8ToBytes("tenant node lsp cell")), index: 0 };

// What each side's cells hold past its share and the fee.
const USER_CHANGE_SHANNONS = 120n * SHANNONS_PER_CKB;

const LSP_CHANGE_SHANNONS = 85n * SHANNONS_PER_CKB;

// CKB testnet's secp256k1_blake160 dep group, which both funding inputs' locks run from.
const SECP256K1_DEP_GROUP: CellDep = {
    outPoint: { txHash: hexToBytes("f8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"), index: 0 },
    depType: "dep_group",
};

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

type OpeningTransition = "CompleteReceivedCommitment" | "SendCommitmentSigned";

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
    commitment: SignedCommitment | null;
    closingTxHash: Uint8Array | null;
};

type BuiltContent = {
    content: SignableContentWire;
    message: Uint8Array;
    settlement: SigningSettlementWire | null;
    commitment: SignedCommitment | null;
    // The cooperative close's, which fiber names the channel's shutdown tx once it lands.
    closingTxHash: Uint8Array | null;
};

type NextMaterial = { point: Uint8Array | null; commitmentNonce: Uint8Array | null; revocationNonce: Uint8Array | null };

type Submission = { channelId: string; requestId: string; partialSignature: Uint8Array; nextMaterial: NextMaterial | null };

type RpcAnswer = { result: unknown } | { error: { code: number; message: string; data?: string } };

type SubmitMethod = "submit_channel_signature" | "submit_watchtower_signature";

type SignedCommitment = { forRemote: boolean; transaction: Transaction; body: Uint8Array; tlcs: WatchtowerTlc[] };

type ForceClosed = {
    forRemote: boolean;
    settlementCellDeps: CellDep[];
    nodeLock: Script;
    medianTimeMs: bigint;
    preimages: Uint8Array[];
    tlcs: WatchtowerTlc[];
    // The commitment lock cell on chain, `null` once no party is left to settle.
    live: WatchtowerCell | null;
};

// A spend fiber's watchtower built, before it waits as a request.
type NodeSpend = {
    requestId: string;
    purpose: WatchtowerKeyPurpose;
    transaction: Transaction;
    commitmentNumber: number;
    tlcEntry: string | null;
    unlock: string;
    txHash: string;
    next: WatchtowerCell | null;
};

type WatchtowerRequest = { purpose: WatchtowerKeyPurpose; transaction: Transaction; served: TenantNodeWatchtowerServed };

type WatchtowerSubmission = { channelId: string; requestId: string; signature: Uint8Array };

// The params of `open_tenant_channel` the double reads (`fiber-json-types/src/channel.rs:182-260`), an absent option `null`.
type OpenRequest = {
    pubkey: Uint8Array;
    fundingShannons: bigint;
    public: boolean | null;
    shutdownScript: Script;
    fundingLockScript: Script;
    // Empty when absent, as fiber defaults them.
    fundingLockScriptCellDeps: CellDep[];
    commitmentDelayEpoch: bigint | null;
    commitmentFeeRate: bigint | null;
    material: ChannelOpenSignerMaterial | null;
};

// Fiber's `TenantChannelOpening` (`fiber/channel.rs:11921`): the command as serde writes it, its channel and the result it froze.
type TenantOpening = { command: string; channelId: string; result: OpenTenantChannelResultWire; terminated: boolean };

// Fiber's `ChannelOpenRecord` (`fiber-types/src/channel.rs:1376`), which outlives an aborted channel's state.
type OpenRecord = {
    channelId: string;
    // The open's, reserve included.
    fundingShannons: bigint;
    createdAtMs: bigint;
    status: "opening" | "ready" | "failed";
    failureDetail: string | null;
};

// The funding of a channel `open_tenant_channel` opened: the tx it froze, and whether the peer's commitment came before it was
// signed.
type ExternalFunding = { unsigned: Transaction; signedSubmitted: boolean; early: boolean };

export type TenantNodeChannel = {
    channelId: string;
    fundingOutPoint: OutPoint;
    commitmentLock: ScriptTemplate;
    fundingLock: ScriptTemplate;
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
    createdAtMs: bigint;
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

// What the next opening's answer states otherwise than the node froze; the device refuses it before it signs anything.
export type TenantNodeOpeningTamper =
    | { kind: "delayEpoch"; commitmentDelayEpoch: string }
    | { kind: "reserve"; side: "local" | "remote"; shannons: string }
    | { kind: "channelId"; channelId: string }
    // Locks output 0 of the funding tx with another script.
    | { kind: "fundingLock"; lock: Script };

export type TenantNodeServed = {
    requestId: string;
    transition: NodeTransition;
    // `<purpose>@<number>`, fiber's `NonceSlot`.
    slot: string;
    // Lowercase hex.
    message: string;
    answers: RpcSubmissionResult[];
};

export type TenantNodeForceClose = {
    // The funding lock's, which fiber adds to the commitment it broadcasts (`fiber/channel.rs:11567-11581`).
    fundingCellDeps: CellDep[];
    // The commitment lock's, ckb-auth's and the secp256k1 dep group's, which every spend carries (`watchtower/actor.rs:1726-1729`).
    settlementCellDeps: CellDep[];
    // The node's secp256k1 lock: its watchtower pays every spend there, and takes the fee from its cells (`actor.rs:1303-1306`).
    nodeLock: Script;
    // The chain's median time, which tells what has expired; the tip is past every delay of the lock.
    medianTimeMs: string;
    // What the node's watchtower holds through `CreatePreimage`, lowercase hex.
    preimages: string[];
    // How many commitments before the view's last one the broadcast one is. Fiber's watchtower settles one it holds the snapshot
    // of (`watchtower/actor.rs:571-579`): the last local one, the last remote one and, until the peer revokes it, the remote one
    // before (`fiber/onchain_tlc_reconcile.rs:128-160`).
    commitmentsBack: number;
};

// Each holds for every spend built once it is set.
export type TenantNodeSpendTamper =
    // Pays the node's output to another lock.
    | { kind: "destination"; lock: Script }
    // Keeps so many shannons of the remainder for the node's output.
    | { kind: "remainder"; shannons: string }
    // Names another key than the one the unlock needs.
    | { kind: "purpose"; purpose: WatchtowerKeyPurpose };

export type TenantNodeWatchtowerServed = {
    requestId: string;
    purpose: WatchtowerKeyPurpose;
    // The version of the commitment the spend descends from.
    commitmentNumber: number;
    // Lowercase hex, `null` for a balance.
    tlcEntry: string | null;
    // As the interop vectors name the spend.
    unlock: string;
    // CKB's `calc_tx_hash`, lowercase hex.
    txHash: string;
    // Output 0, molecule `CellOutput` in lowercase hex, when it is the remainder.
    remainder: string | null;
    answers: RpcSubmissionResult[];
    // The one fiber applied, lowercase hex.
    signature: string | null;
};

export type TenantNodeOnchainTx = { by: "node" | "peer"; what: string; txHash: string };

export type TenantNodeOptions = {
    channel: TenantNodeChannel;
    lspPubkey: Uint8Array;
    // A test shortcut: the node holds only the public parts, but the SDK's builders take the secrets. A channel is built with
    // the keys whose funding key its open's material carries.
    deviceKeys: FiberChannelKeys[];
    peerKeys: FiberChannelKeys;
};

export function tenantNodeChannelOf(vectors: SigningVectors): TenantNodeChannel {
    const { channel } = vectors;
    return {
        channelId: channel.channel_id,
        fundingOutPoint: toOutPoint(channel.funding_out_point),
        commitmentLock: signingCommitmentLock(vectors),
        // The vectors' commitment lock is testnet's.
        fundingLock: FUNDING_LOCK_TESTNET,
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
        // The second the device allocated the channel's index, its clock's reading.
        createdAtMs: BigInt(vectors.device.channel_index) * MILLISECONDS_PER_SECOND,
    };
}

export class InMemoryTenantNode {
    readonly fetch: IFetchLike;

    // The node's side of every channel it opens; an open by RPC takes the rest from the request.
    private readonly terms: TenantNodeChannel;

    // The channel opened last.
    private channel: TenantNodeChannel;

    private readonly lspPubkey: Uint8Array;

    private readonly knownDeviceKeys: readonly FiberChannelKeys[];

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

    private parkNext: SubmitMethod | null = null;

    private dropNext: string | null = null;

    private readonly parked: Record<SubmitMethod, unknown[]> = { submit_channel_signature: [], submit_watchtower_signature: [] };

    // Each view's commitments the device signed, in order: fiber's node broadcasts the latest.
    private readonly signedCommitments: Record<PolicyView, SignedCommitment[]> = { local: [], remote: [] };

    private forceClosed: ForceClosed | null = null;

    // Fiber's `ChannelState` as `list_channels` writes it (`fiber-json-types/src/channel.rs:430-462`), each name whose bits
    // overlap joined by `|` (`serde_utils.rs:475-506`). The handshake's states but the funding tx's collaboration and the wait for
    // its signature are not modeled.
    private channelState: RpcChannelStateWire = { state_name: "ChannelReady" };

    private watchRow = false;

    // The tenant's single opening slot (`fiber/network.rs:3679-3790`).
    private opening: TenantOpening | null = null;

    // By channel id, as fiber's store keys them.
    private readonly records = new Map<string, OpenRecord>();

    private external: ExternalFunding | null = null;

    private readonly openingTampers: TenantNodeOpeningTamper[] = [];

    private commitsEarly = false;

    private shutdownTxHash: Uint8Array | null = null;

    private readonly spendTampers: TenantNodeSpendTamper[] = [];

    // Names the node's cell a spend's fee comes from.
    private sponsorLabel = "node";

    // Fiber's `WatchtowerExternalSignerState` (`fiber-types/src/watchtower.rs:141-154`) less its `last_applied`, which names a
    // request `signed_signatures` keeps too, so both answer a resubmission alike (`rpc/watchtower.rs:424-447`).
    private readonly watchtowerPending = new Map<string, WatchtowerRequest>();

    private readonly watchtowerSigned = new Map<string, WatchtowerRequest>();

    private readonly watchtowerLog: TenantNodeWatchtowerServed[] = [];

    private readonly onchainLog: TenantNodeOnchainTx[] = [];

    constructor(options: TenantNodeOptions) {
        this.terms = options.channel;
        this.channel = options.channel;
        this.lspPubkey = options.lspPubkey;
        this.knownDeviceKeys = options.deviceKeys;
        this.peerKeys = options.peerKeys;
        this.localShannons = options.channel.localShannons;
        this.remoteShannons = options.channel.remoteShannons;
        this.fetch = async (_url: string, init: FetchInit): Promise<FetchResponseLike> => {
            const request = JSON.parse(init.body) as { id: number; method: string; params: unknown[] };
            const params = request.params[0];
            this.sent.push({ method: request.method, params });
            const parkNext = this.parkNext;
            if (parkNext !== null && request.method === parkNext) {
                this.parkNext = null;
                this.parked[parkNext].push(params);
                // Its sender is gone: the answer reaches no one.
                return new Promise<FetchResponseLike>(() => undefined);
            }
            if (request.method === "get_channel_signing_status") await this.beforeThirdSession();
            const body = JSON.stringify({ jsonrpc: "2.0", id: request.id, ...this.answer(request.method, params) });
            if (request.method === this.dropNext) {
                this.dropNext = null;
                throw new TypeError("fetch failed: the connection dropped before the answer");
            }
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

    get watchtowerServed(): TenantNodeWatchtowerServed[] {
        return structuredClone(this.watchtowerLog);
    }

    get onchain(): TenantNodeOnchainTx[] {
        return structuredClone(this.onchainLog);
    }

    openTenantChannel(material: ChannelOpenSignerMaterial, first: OpeningTransition): string {
        const channelId = this.negotiateTenantChannel(material);
        this.completeTxCollaboration(first);
        return channelId;
    }

    // The open up to the funding tx's collaboration: listed already, but fiber creates the tenant's watch row only at
    // `RemoteTxComplete` (`event_handler.rs:41-67`, fired at `fiber/channel.rs:9520-9530`).
    negotiateTenantChannel(material: ChannelOpenSignerMaterial): string {
        this.install(material, this.terms);
        this.channelState = { state_name: "CollaboratingFundingTx", state_flags: "AWAITING_REMOTE_TX_COLLABORATION_MSG" };
        return this.channel.channelId;
    }

    // The two commitments of the open are signed with the channel shown `ChannelReady` already.
    completeTxCollaboration(first: OpeningTransition): void {
        this.collaborate();
        this.markReady();
        this.queueOpening([first, first === "SendCommitmentSigned" ? "CompleteReceivedCommitment" : "SendCommitmentSigned"]);
        this.queueChannelReady(false);
        this.drain();
    }

    // The next opening's answer states the tampered value; the double's channel keeps the one it froze.
    tamperOpening(tamper: TenantNodeOpeningTamper): void {
        this.openingTampers.push(tamper);
    }

    // The next opening's peer sends its commitment_signed before the funding tx is signed, as fiber allows
    // (`fiber/channel.rs:4086-4095`): the device's own commitment is asked for while the opening waits.
    receiveCommitmentEarly(): void {
        this.commitsEarly = true;
    }

    // Fiber's external funding timeout, 300 s by default (`fiber/config.rs:97`), fired (`fiber/channel.rs:4374-4395`): the channel
    // stops `Closed(FUNDING_ABORTED)`, the tenant's opening terminated (`fiber/network.rs:2574-2586`), its open record failed with
    // the detail (`:2588-2620`) and its state deleted (`:8387-8398`) with its watch row (`event_handler.rs:186-191`).
    expireOpening(): void {
        if (this.material === null || this.external === null || this.external.signedSubmitted) {
            throw new Error("no opening waits for its signed funding tx");
        }
        const { channelId } = this.channel;
        const record = this.recordOf(channelId);
        record.status = "failed";
        // The id in its display form, the state in its debug form (`fiber/channel.rs:4385-4390`), bitflags naming the flags held whole.
        const state =
            this.channelState.state_name === "SigningCommitment"
                ? "SigningCommitment(SigningCommitmentFlags(THEIR_COMMITMENT_SIGNED_SENT))"
                : "NegotiatingFunding(NegotiatingFundingFlags(AWAITING_EXTERNAL_FUNDING))";
        record.failureDetail = `[Channel Hash256(${channelId})] External funding transaction submission timed out in state ${state}`;
        if (this.opening?.channelId === channelId) this.opening.terminated = true;
        this.forgetChannel();
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
        // Both shutdowns exchanged and no TLC left, as fiber asks for the closing signature (`channel.rs:9158-9169`).
        this.channelState = {
            state_name: "ShuttingDown",
            state_flags: "OUR_SHUTDOWN_SENT|THEIR_SHUTDOWN_SENT|AWAITING_PENDING_TLCS|DROPPING_PENDING",
        };
        this.queue.push({ kind: "request", transition: "SendClosingSigned", state: this.state() });
        this.drain();
    }

    // The node, or the peer for the remote view, puts the view's commitment on chain; the node's watchtower then spends it.
    forceClose(view: PolicyView, options: TenantNodeForceClose): void {
        if (this.channelState.state_name === "Closed") throw new Error("the channel is already closed");
        const commitment = this.signedCommitments[view].at(-1 - options.commitmentsBack);
        if (commitment === undefined)
            throw new Error(`the device signed no commitment ${options.commitmentsBack} before the ${view} view's last`);
        // The close ends the exchange: the request in flight and those queued behind it are never served.
        this.pending = null;
        this.queue.length = 0;
        const [output] = commitment.transaction.outputs;
        if (output === undefined) throw new Error("a commitment holds its cell at output 0");
        // Its on-chain hash covers the funding lock's cell deps fiber adds (`fiber/channel.rs:11567-11581`).
        const txHash = computeTxHash({ ...commitment.transaction, cellDeps: options.fundingCellDeps });
        this.forceClosed = {
            forRemote: commitment.forRemote,
            settlementCellDeps: options.settlementCellDeps,
            nodeLock: options.nodeLock,
            medianTimeMs: BigInt(options.medianTimeMs),
            preimages: options.preimages.map(hexToBytes),
            tlcs: commitment.tlcs,
            live: { outPoint: { txHash, index: 0 }, output, body: commitment.body, first: true },
        };
        this.onchainLog.push({ by: view === "local" ? "node" : "peer", what: `${view} commitment`, txHash: bytesToHex(txHash) });
        // Named once confirmed, either close (`channel.rs:11679`).
        this.shutdownTxHash = txHash;
        // From the broadcast fiber's own commitment is `ShuttingDown(WAITING_COMMITMENT_CONFIRMATION)` (`channel.rs:2723`) and,
        // confirmed, as it is here at once, `Closed` (`:11665-11673`).
        const side = view === "local" ? "UNCOOPERATIVE_LOCAL" : "UNCOOPERATIVE_REMOTE";
        this.channelState = { state_name: "Closed", state_flags: `${side}|WAITING_ONCHAIN_SETTLEMENT` };
    }

    // The peer's own watchtower spends the cell first, as fiber's would from its side, once what the device signed has landed.
    peerSpend(): void {
        const closed = this.requireForceClosed();
        this.runWatchtower(closed, false);
        const cell = closed.live;
        if (cell === null) throw new Error("no commitment lock cell is left to spend");
        const party: WatchtowerParty = {
            forRemote: !closed.forRemote,
            settlementKeyHash: blake160(pubkeyOf(this.peerKeys.tlcBaseKey)),
            offered: "received",
            // None, as in the interop vectors: the payee of the device's outbound TLC keeps its preimage.
            preimages: [],
        };
        const pick = pickWatchtowerUnlock(cell, closed.tlcs, party, closed.medianTimeMs);
        if (pick === null) throw new Error("the peer has nothing to spend");
        // Its close script stands for its node's lock; its signatures leave the hash unchanged.
        const lock = this.channel.remoteCloseScript;
        const context = { cellDeps: closed.settlementCellDeps, sponsorLabel: "peer", payTo: lock, remainderShortfallShannons: 0n };
        const { transaction, next } = buildWatchtowerSpend(cell, pick, party, context);
        closed.live = next;
        this.onchainLog.push({ by: "peer", what: pick.label, txHash: bytesToHex(computeTxHash(transaction)) });
    }

    passTime(medianTimeMs: string): void {
        this.requireForceClosed().medianTimeMs = BigInt(medianTimeMs);
    }

    // The node's watchtower pays the fee of every spend it builds from now on from another of its cells: the spend waiting is
    // rebuilt under a new request, and fiber keeps the one it supersedes pending (`watchtower/actor.rs:2151-2155`).
    fundSpendsFrom(sponsorLabel: string): void {
        this.sponsorLabel = sponsorLabel;
    }

    tamperSpends(tamper: TenantNodeSpendTamper): void {
        this.spendTampers.push(tamper);
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
    parkNextSubmission(method: SubmitMethod = "submit_channel_signature"): void {
        this.parkNext = method;
    }

    // The node handles the method's next call, and the connection drops before its answer.
    dropNextAnswer(method: string): void {
        this.dropNext = method;
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
                return this.listChannels(params);
            case "open_tenant_channel":
                return this.openChannelByRpc(params);
            case "submit_signed_funding_tx":
                return this.submitSignedFundingTx(params);
            case "get_channel_signing_status":
                return this.signingStatus(params);
            case "submit_channel_signature":
                for (const parked of this.parked.submit_channel_signature.splice(0)) this.submit(parked);
                return this.submit(params);
            case "get_watchtower_signing_status":
                return this.watchtowerStatus(params);
            case "submit_watchtower_signature":
                for (const parked of this.parked.submit_watchtower_signature.splice(0)) this.watchtowerSubmit(parked);
                return this.watchtowerSubmit(params);
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
        // `finish_received_commitment_signed` (`fiber/channel.rs:2525-2550`): the peer's commitment taken while the funding waits.
        if (pending.transition === "CompleteReceivedCommitment" && this.channelState.state_flags === "AWAITING_EXTERNAL_FUNDING") {
            this.channelState = { state_name: "SigningCommitment", state_flags: "THEIR_COMMITMENT_SIGNED_SENT|COMMITMENT_SIGNED_SENT" };
        }
        // The close lands and confirms at once (`channel.rs:9236`, `:11676`).
        if (pending.transition === "SendClosingSigned") {
            this.channelState = { state_name: "Closed", state_flags: "COOPERATIVE" };
            this.shutdownTxHash = pending.closingTxHash;
        }
        if (pending.commitment !== null) this.signedCommitments[pending.commitment.forRemote ? "remote" : "local"].push(pending.commitment);
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
            commitment: built.commitment,
            closingTxHash: built.closingTxHash,
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

    private contentOf(transition: NodeTransition, slot: NodeSlot, state: CommitmentState, tamper: TenantNodeTamper | null): BuiltContent {
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
    ): BuiltContent & { settlement: SigningSettlementWire; commitment: SignedCommitment } {
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
        const keys = this.deviceKeys();
        const transaction = buildCommitmentTx(keys, input);
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
            commitment: {
                forRemote,
                transaction,
                body: buildCommitmentSettlementWitness(keys, input),
                tlcs: trackWatchtowerTlcs(keys, input),
            },
            closingTxHash: null,
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

    private revocationContent(forRemote: boolean, revokedCommitmentNumber: number): BuiltContent {
        const input: RevocationInput = {
            ...this.commitmentTerms(),
            forRemote,
            revokedCommitmentNumber,
            // Sending revokes the device's commitment to the peer's benefit; receiving, the peer's to the device's.
            payoutScript: forRemote ? this.channel.localCloseScript : this.channel.remoteCloseScript,
            commitmentDelayEpoch: this.channel.commitmentDelayEpoch,
        };
        const { output, outputData, commitmentLockArgs } = buildRevocationContent(this.deviceKeys(), input);
        return {
            content: {
                type: "Revocation",
                output: encodeAnyHexBytes("output", moleculeCellOutput(output.capacityShannons, output.lock, output.type)),
                output_data: encodeAnyHexBytes("outputData", outputData),
                commitment_lock_script_args: encodeHexBytes("commitmentLockArgs", commitmentLockArgs, REVOCATION_LOCK_ARGS_LENGTH),
            },
            message: computeRevocationContentMessage(output, outputData, commitmentLockArgs),
            settlement: null,
            commitment: null,
            closingTxHash: null,
        };
    }

    // Fiber's `build_shutdown_tx`: each side's total less its own fee.
    private closingContent(state: CommitmentState, tamper: TenantNodeTamper | null): BuiltContent {
        const { channel } = this;
        const localCloseScript = tamper?.kind === "closeScript" ? tamper.script : channel.localCloseScript;
        const sizing = {
            cellDepsCount: channel.fundingLockCellDepsCount,
            udtTypeScript: null,
            localCloseScript,
            remoteCloseScript: channel.remoteCloseScript,
        };
        const transaction = buildClosingTx(
            this.deviceKeys(),
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
            commitment: null,
            closingTxHash: computeTxHash(transaction),
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

    // Fiber's `list_channels` (`rpc/channel.rs:506-680`): the channel while its state is stored, closed (`fiber-types/src/
    // channel.rs:297-303`) only to a call that asks for closed ones; to one that asks for pending ones, the channel while it opens
    // (`fiber-json-types/src/convert.rs:143-158`) and each failed opening whose state is gone, as fiber makes it up.
    private listChannels(params: unknown): RpcAnswer {
        const filter = readParams<ListChannelsParamsWire, { includeClosed: boolean; onlyPending: boolean }>(params, (at) => ({
            includeClosed: readOption(at("include_closed"), decodeBoolean) ?? false,
            onlyPending: readOption(at("only_pending"), decodeBoolean) ?? false,
        }));
        if (filter instanceof WireError) return invalidParams(params, filter);
        const { includeClosed, onlyPending } = filter;
        if (includeClosed && onlyPending) return failed("only_pending and include_closed are mutually exclusive");
        const channels: RpcChannelWire[] = [];
        if (this.material !== null) {
            const name = this.channelState.state_name;
            // A closed channel is pending only as an aborted opening, whose state fiber deletes.
            const pending = name !== "ChannelReady" && name !== "ShuttingDown" && name !== "Closed";
            if (onlyPending ? pending : includeClosed || name !== "Closed") channels.push(this.listedChannel());
        }
        if (onlyPending) {
            // A record still opening keeps its state here.
            const failedRecords = [...this.records.values()].filter((record) => record.status === "failed");
            channels.push(...failedRecords.map((record) => this.abortedChannel(record)));
        }
        return { result: { channels } };
    }

    // Fiber's `to_local_amount` keeps an offered TLC until it is fulfilled (`fiber/channel.rs:8195-8225`), where the double's
    // balance moves it at once.
    private listedChannel(): RpcChannelWire {
        const { channel, shutdownTxHash } = this;
        const inFlight = (direction: TlcDirection): bigint =>
            this.tlcs.filter((tlc) => tlc.direction === direction).reduce((sum, tlc) => sum + tlc.amountShannons, 0n);
        const offered = inFlight("offered");
        const received = inFlight("received");
        return {
            channel_id: channel.channelId,
            pubkey: encodeBareHexBytes("pubkey", this.lspPubkey, COMPRESSED_POINT_LENGTH),
            funding_udt_type_script: null,
            state: structuredClone(this.channelState),
            local_balance: encodeUintHex("localBalance", this.localShannons + offered, UINT128_MAX),
            offered_tlc_balance: encodeUintHex("offeredTlcBalance", offered, UINT128_MAX),
            remote_balance: encodeUintHex("remoteBalance", this.remoteShannons + received, UINT128_MAX),
            received_tlc_balance: encodeUintHex("receivedTlcBalance", received, UINT128_MAX),
            created_at: encodeUintHex("createdAt", channel.createdAtMs, UINT64_MAX),
            shutdown_transaction_hash:
                shutdownTxHash === null ? null : encodeHexBytes("shutdownTransactionHash", shutdownTxHash, HASH256_LENGTH),
            failure_detail: this.recordOf(channel.channelId).failureDetail,
        };
    }

    // The entry fiber makes up for a failed opening (`rpc/channel.rs:601-680`): the open's amount on the tenant's side.
    private abortedChannel(record: OpenRecord): RpcChannelWire {
        return {
            channel_id: record.channelId,
            pubkey: encodeBareHexBytes("pubkey", this.lspPubkey, COMPRESSED_POINT_LENGTH),
            funding_udt_type_script: null,
            state: { state_name: "Closed", state_flags: "FUNDING_ABORTED" },
            local_balance: encodeUintHex("localBalance", record.fundingShannons, UINT128_MAX),
            offered_tlc_balance: encodeUintHex("offeredTlcBalance", 0n, UINT128_MAX),
            remote_balance: encodeUintHex("remoteBalance", 0n, UINT128_MAX),
            received_tlc_balance: encodeUintHex("receivedTlcBalance", 0n, UINT128_MAX),
            created_at: encodeUintHex("createdAt", record.createdAtMs, UINT64_MAX),
            shutdown_transaction_hash: null,
            failure_detail: record.failureDetail,
        };
    }

    // `open_tenant_channel` (`rpc/channel.rs:345-370`): the params checked (`:1110-1124`), then the network actor's single opening
    // per tenant (`fiber/network.rs:3679-3790`). Never parked: the double freezes the funding tx within the call.
    private openChannelByRpc(params: unknown): RpcAnswer {
        const request = readParams<OpenTenantChannelParamsWire, OpenRequest>(params, readOpenRequest);
        if (request instanceof WireError) return invalidParams(params, request);
        if (!equalBytes(request.pubkey, this.lspPubkey)) return failed("tenant channel peer must be the LSP public node");
        if (request.public !== false) return failed("tenant channel requires public: false");
        const { material } = request;
        if (material === null) return failed("tenant channel requires external_channel_signer");
        // Fiber compares the commands it converts the params to, the material's nonces included.
        const command = canonicalJson(openCommandOf(params));
        const { opening } = this;
        if (opening !== null && !opening.terminated) {
            if (opening.command !== command) return failed("tenant already has a different channel opening");
            if (this.recordOf(opening.channelId).status === "ready") return failed("tenant channel is already open");
            return { result: structuredClone(opening.result) };
        }
        // A terminated opening is cleared; only a failed record lets another open.
        this.opening = null;
        if ([...this.records.values()].some((record) => record.status !== "failed")) return failed("tenant already has a channel");
        const result = this.openExternallyFunded(request, material);
        this.opening = { command, channelId: this.channel.channelId, result, terminated: false };
        return { result: structuredClone(result) };
    }

    // The channel fiber's actor opens (`fiber/channel.rs:4913-4960`), through `TxComplete` into the wait for the host's signature
    // (`:4155-4167`), and its frozen terms (`:5911-5944`). The tenant's reserve covers the open's shutdown script
    // (`get_funding_and_reserved_amount`, `:4946-4951`, `:5811-5851`); the LSP's is the vectors', over its own.
    private openExternallyFunded(request: OpenRequest, material: ChannelOpenSignerMaterial): OpenTenantChannelResultWire {
        const { terms } = this;
        const localReserved = reservedCkbShannons(request.shutdownScript, terms.lockLayout);
        const remoteReserved = terms.remoteReservedCkbShannons;
        if (request.fundingShannons < localReserved) throw new Error("the double opens no channel its funding cannot reserve");
        const peerFundingPubkey = pubkeyOf(this.peerKeys.fundingKey);
        const peerTlcBasePubkey = pubkeyOf(this.peerKeys.tlcBaseKey);
        const localAmount = request.fundingShannons;
        const remoteAmount = terms.remoteShannons + remoteReserved;
        const commitmentDelayEpoch = request.commitmentDelayEpoch ?? terms.commitmentDelayEpoch;
        const commitmentFeeRate = request.commitmentFeeRate ?? terms.commitmentFeeRate;
        const channelId = tenantChannelId(material.tlcBaseKey, peerTlcBasePubkey);
        const fundingLock: Script = { ...terms.fundingLock, args: fundingLockArgs(material.fundingPubkey, peerFundingPubkey) };
        const stated = { channelId, commitmentDelayEpoch, localReserved, remoteReserved, fundingLock };
        for (const tamper of this.openingTampers.splice(0)) {
            switch (tamper.kind) {
                case "delayEpoch":
                    stated.commitmentDelayEpoch = BigInt(tamper.commitmentDelayEpoch);
                    break;
                case "reserve":
                    stated[tamper.side === "local" ? "localReserved" : "remoteReserved"] = BigInt(tamper.shannons);
                    break;
                case "channelId":
                    stated.channelId = tamper.channelId;
                    break;
                case "fundingLock":
                    stated.fundingLock = tamper.lock;
            }
        }
        const unsigned = this.fundingTx(stated.fundingLock, localAmount + remoteAmount, request);
        this.install(material, {
            ...terms,
            channelId,
            fundingOutPoint: { txHash: computeTxHash(unsigned), index: 0 },
            commitmentDelayEpoch,
            commitmentFeeRate,
            localShannons: localAmount - localReserved,
            localReservedCkbShannons: localReserved,
            remoteReservedCkbShannons: remoteReserved,
            localCloseScript: request.shutdownScript,
        });
        this.collaborate();
        this.channelState = { state_name: "NegotiatingFunding", state_flags: "AWAITING_EXTERNAL_FUNDING" };
        this.external = { unsigned, signedSubmitted: false, early: this.commitsEarly };
        if (this.commitsEarly) {
            this.queueOpening(["CompleteReceivedCommitment"]);
            this.drain();
        }
        this.commitsEarly = false;
        return {
            channel_id: stated.channelId,
            unsigned_funding_tx: encodeTransaction("unsignedFundingTx", unsigned),
            opening_context: {
                remote_funding_key: encodeBareHexBytes("remoteFundingKey", peerFundingPubkey, COMPRESSED_POINT_LENGTH),
                remote_settlement_key: encodeBareHexBytes("remoteSettlementKey", peerTlcBasePubkey, COMPRESSED_POINT_LENGTH),
                remote_shutdown_script: encodeScript("remoteShutdownScript", terms.remoteCloseScript),
                commitment_delay_epoch: encodeUintHex("commitmentDelayEpoch", stated.commitmentDelayEpoch, UINT64_MAX),
                commitment_fee_rate: encodeUintHex("commitmentFeeRate", commitmentFeeRate, UINT64_MAX),
                local_amount: encodeUintHex("localAmount", localAmount, UINT128_MAX),
                remote_amount: encodeUintHex("remoteAmount", remoteAmount, UINT128_MAX),
                local_reserved_ckb_amount: encodeUintHex("localReservedCkbAmount", stated.localReserved, UINT64_MAX),
                remote_reserved_ckb_amount: encodeUintHex("remoteReservedCkbAmount", stated.remoteReserved, UINT64_MAX),
            } satisfies TenantChannelOpeningContextWire,
        };
    }

    // Output 0 the funding cell, then the opener's change and the LSP's, as `assemble_base_tx` appends a builder's outputs after
    // the ones it received (`ckb/funding/funding_tx.rs:552-600`), with a placeholder for each input's lock. The open's extra deps
    // of the user's lock follow the tx's own, each once (`:714-726`).
    private fundingTx(fundingLock: Script, capacityShannons: bigint, request: OpenRequest): Transaction {
        const cellDeps = [SECP256K1_DEP_GROUP];
        for (const dep of request.fundingLockScriptCellDeps) if (!cellDeps.some((held) => sameCellDep(held, dep))) cellDeps.push(dep);
        return {
            version: 0,
            cellDeps,
            headerDeps: [],
            inputs: [USER_CELL, LSP_CELL].map((previousOutput) => ({ since: 0n, previousOutput })),
            outputs: [
                { capacityShannons, lock: fundingLock, type: null },
                { capacityShannons: USER_CHANGE_SHANNONS, lock: request.fundingLockScript, type: null },
                // The LSP's close script stands for its wallet's lock.
                { capacityShannons: LSP_CHANGE_SHANNONS, lock: this.terms.remoteCloseScript, type: null },
            ],
            outputsData: [new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)],
            witnesses: [SECP_PLACEHOLDER_WITNESS, SECP_PLACEHOLDER_WITNESS],
        };
    }

    // `submit_signed_funding_tx` (`rpc/channel.rs:799-816`): the network actor's lookup (`fiber/network.rs:3832-3842`), then
    // `handle_submit_external_funding_tx` (`fiber/channel.rs:4075-4125`), whose commitment signing resumes the open.
    private submitSignedFundingTx(params: unknown): RpcAnswer {
        const submission = readParams<SubmitSignedFundingTxParamsWire, { channelId: string; signed: Transaction }>(params, (at) => ({
            channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
            signed: decodeTransaction(at("signed_funding_tx")),
        }));
        if (submission instanceof WireError) return invalidParams(params, submission);
        // The id in `Hash256`'s debug form.
        if (!this.isChannel(submission.channelId)) return failed(`Channel not found error: Hash256(${submission.channelId})`);
        const funding = this.external;
        if (funding === null) throw new Error("the double serves submit_signed_funding_tx only to a channel open_tenant_channel opened");
        if (funding.signedSubmitted) return failed("Repeated processing message: Signed funding tx has already been submitted");
        // The hash covers the raw transaction, the witnesses aside.
        const txHash = computeTxHash(submission.signed);
        if (!equalBytes(txHash, computeTxHash(funding.unsigned))) {
            return failed(
                "Invalid parameter: Signed funding transaction raw data mismatch; only witnesses may change for external funding",
            );
        }
        funding.signedSubmitted = true;
        // `install_external_funding_signed_tx`, called keeping a signing state (`fiber/channel.rs:4007-4022`, `:4109`).
        if (this.channelState.state_name !== "SigningCommitment") {
            this.channelState = {
                state_name: "CollaboratingFundingTx",
                state_flags: "OUR_TX_COMPLETE_SENT|THEIR_TX_COMPLETE_SENT|COLLABORATION_COMPLETED",
            };
        }
        this.queueOpening(funding.early ? ["SendCommitmentSigned"] : ["SendCommitmentSigned", "CompleteReceivedCommitment"]);
        this.queueChannelReady(true);
        this.drain();
        return { result: { channel_id: submission.channelId, funding_tx_hash: encodeHexBytes("fundingTxHash", txHash, HASH256_LENGTH) } };
    }

    // Installed as fiber's `apply_open_signer_material` does (`channel.rs:5958-6005`); a tenant channel has no announcement. The
    // open record is written at the open (`fiber/network.rs:7549-7555`), over any of the same id.
    private install(material: ChannelOpenSignerMaterial, channel: TenantNodeChannel): void {
        if (this.material !== null) throw new Error("the node already opened its channel");
        this.material = material;
        this.channel = channel;
        this.localShannons = channel.localShannons;
        this.remoteShannons = channel.remoteShannons;
        this.points.set(1, material.firstCommitmentPoint);
        this.points.set(2, material.secondCommitmentPoint);
        this.nonces.set(slotKey({ purpose: "Commitment", commitmentNumber: 0 }), material.commitmentNonce);
        this.nonces.set(slotKey({ purpose: "Commitment", commitmentNumber: 1 }), material.nextCommitmentNonce);
        this.nonces.set(slotKey({ purpose: "Revocation", commitmentNumber: 2 }), material.revocationNonce);
        this.records.set(channel.channelId, {
            channelId: channel.channelId,
            fundingShannons: channel.localShannons + channel.localReservedCkbShannons,
            createdAtMs: channel.createdAtMs,
            status: "opening",
            failureDetail: null,
        });
    }

    // `TxComplete`: the watch row exists from here on (`event_handler.rs:41-67`, fired at `fiber/channel.rs:9520-9530`); R+1 at
    // TxComplete (`channel.rs:9545`), L+1 entering the wait for the external funding (`:4161`).
    private collaborate(): void {
        if (this.watchRow) throw new Error("the funding tx's collaboration already completed");
        this.watchRow = true;
        this.remote += 1;
        this.local += 1;
    }

    private queueOpening(transitions: readonly OpeningTransition[]): void {
        const state = this.state();
        this.queue.push(...transitions.map((transition): Step => ({ kind: "request", transition, state })));
    }

    // ChannelReady moves both counters (`channel.rs:9905`); an open by RPC is shown ready only then.
    private queueChannelReady(shown: boolean): void {
        this.queue.push({
            kind: "event",
            run: () => {
                this.local += 1;
                this.remote += 1;
                if (shown) this.markReady();
            },
        });
    }

    private markReady(): void {
        this.channelState = { state_name: "ChannelReady" };
        this.recordOf(this.channel.channelId).status = "ready";
    }

    // The channel's state is gone; its open record and the logs stay.
    private forgetChannel(): void {
        this.material = null;
        this.local = 0;
        this.remote = 0;
        this.points.clear();
        this.nonces.clear();
        this.tlcs = [];
        this.nextTlcIds = { offered: 0, received: 0 };
        this.queue.length = 0;
        this.pending = null;
        this.lastApplied = null;
        this.signedCommitments.local.length = 0;
        this.signedCommitments.remote.length = 0;
        this.forceClosed = null;
        this.watchRow = false;
        this.external = null;
        this.shutdownTxHash = null;
        this.watchtowerPending.clear();
        this.watchtowerSigned.clear();
    }

    private recordOf(channelId: string): OpenRecord {
        const record = this.records.get(channelId);
        if (record === undefined) throw new Error(`the node holds no open record of ${channelId}`);
        return record;
    }

    private deviceKeys(): FiberChannelKeys {
        const { fundingPubkey } = this.openMaterial();
        const keys = this.knownDeviceKeys.find((candidate) => equalBytes(pubkeyOf(candidate.fundingKey), fundingPubkey));
        if (keys === undefined) throw new Error(`the node holds no device keys under the funding key ${bytesToHex(fundingPubkey)}`);
        return keys;
    }

    // A cooperative close deletes the tenant's watch row (`event_handler.rs:186-191`, wired at `lsp/runtime.rs:214-222`); a force
    // close emits no `ChannelClosed` (`network.rs:8340-8346`).
    private isWatched(channelId: string): boolean {
        return this.isChannel(channelId) && this.watchRow && this.channelState.state_flags !== "COOPERATIVE";
    }

    // `get_watchtower_signing_status` (`rpc/watchtower.rs:379-400`) once the watchtower has checked the cell on chain.
    private watchtowerStatus(params: unknown): RpcAnswer {
        const channelId = readParams<RpcChannelIdParamsWire, string>(params, (at) => requireHexBytes(at("channel_id"), HASH256_LENGTH));
        if (channelId instanceof WireError) return invalidParams(params, channelId);
        if (!this.isWatched(channelId)) return failed("watched channel not found");
        if (this.forceClosed !== null) this.runWatchtower(this.forceClosed, true);
        // The `first_pending` of a map ordered by request id (`fiber-types/src/watchtower.rs:160-162`).
        const [requestId] = [...this.watchtowerPending.keys()].sort();
        const request = this.watchtowerPending.get(requestId ?? "");
        const status: WatchtowerSigningStatusWire =
            request === undefined
                ? { type: "NoSignatureRequired" }
                : {
                      type: "SignatureRequired",
                      request_id: request.served.requestId,
                      content: {
                          key_purpose: keyPurposeWire(request.purpose),
                          transaction: encodeTransaction("transaction", request.transaction),
                      },
                  };
        return { result: { channel_id: channelId, status } };
    }

    // `submit_watchtower_signature` (`rpc/watchtower.rs:402-472`), its checks in order: a refusal writes nothing, so the request
    // stays pending. The device's channel always has an external signer.
    private watchtowerSubmit(params: unknown): RpcAnswer {
        const submission = readParams<SubmitWatchtowerSignatureParamsWire, WatchtowerSubmission>(params, (at) => ({
            channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
            requestId: requireHexBytes(at("request_id"), HASH256_LENGTH),
            // A `Vec<u8>` (`fiber-json-types/src/channel.rs:1014-1017`): any length reads, the handler refuses.
            signature: decodeAnyHexBytes(at("signature")),
        }));
        if (submission instanceof WireError) return invalidParams(params, submission);
        const { channelId, requestId, signature } = submission;
        if (signature.length !== RECOVERABLE_ECDSA_SIGNATURE_LENGTH) return failed("watchtower signature must be 65 bytes");
        if (!this.isWatched(channelId)) return failed("watched channel not found");
        const signed = this.watchtowerSigned.get(requestId);
        if (signed !== undefined) {
            if (signed.served.signature !== bytesToHex(signature)) {
                return failed("submitted signature does not match the previously applied result");
            }
            signed.served.answers.push("AlreadyApplied");
            return { result: { type: "AlreadyApplied" } };
        }
        const request = this.watchtowerPending.get(requestId);
        if (request === undefined) return failed("signature request id not found in pending requests");
        const expected = this.expectedOnchainPubkey(request.purpose);
        if (typeof expected === "string") return failed(expected);
        const refusal = verifyWatchtowerSignature(expected, computeTxMessage(request.transaction), signature);
        if (refusal !== null) return failed(refusal);
        this.watchtowerPending.delete(requestId);
        this.watchtowerSigned.set(requestId, request);
        request.served.answers.push("Applied");
        request.served.signature = bytesToHex(signature);
        return { result: { type: "Applied" } };
    }

    // `expected_onchain_pubkey` (`fiber-types/src/watchtower.rs:184-223`) over the local, remote and pending remote snapshots: the
    // last local commitment and the last two remote ones. Every key at a number derives alike, so its conflict check never fires.
    private expectedOnchainPubkey(purpose: WatchtowerKeyPurpose): Uint8Array | string {
        const { tlcBaseKey } = this.openMaterial();
        if (purpose.kind === "settlement") return tlcBaseKey;
        const { commitmentNumber } = purpose;
        const { local, remote } = this.signedCommitments;
        const snapshots = [local.at(-1), remote.at(-2), remote.at(-1)];
        if (!snapshots.some((snapshot) => snapshot?.tlcs.some((tlc) => tlc.localKeyCommitmentNumber === commitmentNumber))) {
            return `TLC signing key not found for derivation index ${commitmentNumber}`;
        }
        return derivePublicKey(tlcBaseKey, this.publishedPoint(commitmentNumber));
    }

    // Fiber's periodic check (`watchtower/actor.rs:558-873`, `:2082-2175`), collapsed: the spend of the cell on chain lands once
    // signed and the check goes on with its remainder; one unsigned waits as a request, unless the peer's spend lands first.
    private runWatchtower(closed: ForceClosed, waits: boolean): void {
        for (let spend = this.nodeSpend(closed); spend !== null; spend = this.nodeSpend(closed)) {
            if (!this.watchtowerSigned.has(spend.requestId)) {
                if (waits && !this.watchtowerPending.has(spend.requestId)) this.waitFor(spend);
                return;
            }
            closed.live = spend.next;
            this.onchainLog.push({ by: "node", what: spend.unlock, txHash: spend.txHash });
        }
    }

    private nodeSpend(closed: ForceClosed): NodeSpend | null {
        const cell = closed.live;
        if (cell === null) return null;
        const party: WatchtowerParty = {
            forRemote: closed.forRemote,
            settlementKeyHash: blake160(this.openMaterial().tlcBaseKey),
            offered: "offered",
            preimages: closed.preimages,
        };
        const pick = pickWatchtowerUnlock(cell, closed.tlcs, party, closed.medianTimeMs);
        if (pick === null) return null;
        const context: WatchtowerSpendContext = {
            cellDeps: closed.settlementCellDeps,
            sponsorLabel: this.sponsorLabel,
            payTo: closed.nodeLock,
            remainderShortfallShannons: 0n,
        };
        let { purpose } = pick;
        for (const tamper of this.spendTampers) {
            if (tamper.kind === "destination") context.payTo = tamper.lock;
            else if (tamper.kind === "remainder") context.remainderShortfallShannons = BigInt(tamper.shannons);
            else purpose = tamper.purpose;
        }
        const { transaction, next } = buildWatchtowerSpend(cell, pick, party, context);
        return {
            requestId: encodeHexBytes("requestId", watchtowerRequestId(transaction), HASH256_LENGTH),
            purpose,
            transaction,
            // Fiber reads it from the lock args, which every remainder keeps (`watchtower/actor.rs:1268-1269`).
            commitmentNumber: readCommitmentLockVersion(cell.output.lock.args),
            tlcEntry: pick.record === null ? null : bytesToHex(pick.record),
            unlock: pick.label,
            txHash: bytesToHex(computeTxHash(transaction)),
            next,
        };
    }

    private waitFor(spend: NodeSpend): void {
        const { requestId, purpose, transaction, commitmentNumber, tlcEntry, unlock, txHash, next } = spend;
        const remainder =
            next === null ? null : bytesToHex(moleculeCellOutput(next.output.capacityShannons, next.output.lock, next.output.type));
        const served: TenantNodeWatchtowerServed = {
            requestId,
            purpose,
            commitmentNumber,
            tlcEntry,
            unlock,
            txHash,
            remainder,
            answers: [],
            signature: null,
        };
        this.watchtowerLog.push(served);
        this.watchtowerPending.set(requestId, { purpose, transaction, served });
    }

    private requireForceClosed(): ForceClosed {
        if (this.forceClosed === null) throw new Error("the channel was never force closed");
        return this.forceClosed;
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

function keyPurposeWire(purpose: WatchtowerKeyPurpose): OnchainKeyPurposeWire {
    if (purpose.kind === "settlement") return { type: "Settlement" };
    return { type: "Tlc", commitment_number: encodeUintHexNumber("commitmentNumber", purpose.commitmentNumber, MAX_COMMITMENT_NUMBER) };
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
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        requestId: requireHexBytes(at("request_id"), HASH256_LENGTH),
        partialSignature: decodeHexBytes(at("partial_signature"), PARTIAL_SIGNATURE_LENGTH),
        nextMaterial: readOption(at("next_material"), readNextMaterial),
    };
}

// Each member optional, as fiber's own type has them, so a missing one gets fiber's refusal rather than a parse error.
function readNextMaterial(field: WireField): NextMaterial {
    const at = readObject<NextChannelSignerMaterialWire>(field);
    return {
        point: readOption(at("next_commitment_point"), (member) => decodeBareHexBytes(member, COMPRESSED_POINT_LENGTH)),
        // `Option<SliceHex>` over a `Vec<u8>` (`fiber-json-types/src/channel.rs:912-919`): any length reads, the submit refuses.
        commitmentNonce: readOption(at("next_commitment_nonce"), decodeAnyHexBytes),
        revocationNonce: readOption(at("next_revocation_nonce"), decodeAnyHexBytes),
    };
}

function readOpenRequest(at: (name: keyof OpenTenantChannelParamsWire & string) => WireField): OpenRequest {
    const readUint64 = (field: WireField): bigint => decodeUintHex(field, UINT64_MAX);
    return {
        pubkey: decodeBareHexBytes(at("pubkey"), COMPRESSED_POINT_LENGTH),
        fundingShannons: decodeUintHex(at("funding_amount"), UINT128_MAX),
        public: readOption(at("public"), decodeBoolean),
        shutdownScript: decodeScript(at("shutdown_script")),
        fundingLockScript: decodeScript(at("funding_lock_script")),
        fundingLockScriptCellDeps: readOption(at("funding_lock_script_cell_deps"), (field) => readArray(field).map(decodeCellDep)) ?? [],
        commitmentDelayEpoch: readOption(at("commitment_delay_epoch"), readUint64),
        commitmentFeeRate: readOption(at("commitment_fee_rate"), readUint64),
        material: readOption(at("external_channel_signer"), readOpenMaterial),
    };
}

function readOpenMaterial(field: WireField): ChannelOpenSignerMaterial {
    const at = readObject<ChannelOpenSignerMaterialWire>(field);
    const keys = readObject<ChannelOpenSignerMaterialWire["base_public_keys"]>(at("base_public_keys"));
    const readPoint = (member: WireField): Uint8Array => decodeBareHexBytes(member, COMPRESSED_POINT_LENGTH);
    const readNonce = (member: WireField): Uint8Array => decodeHexBytes(member, PUBLIC_NONCE_LENGTH);
    return {
        fundingPubkey: readPoint(keys("funding_pubkey")),
        tlcBaseKey: readPoint(keys("tlc_base_key")),
        firstCommitmentPoint: readPoint(at("first_commitment_point")),
        secondCommitmentPoint: readPoint(at("second_commitment_point")),
        commitmentNonce: readNonce(at("commitment_nonce")),
        nextCommitmentNonce: readNonce(at("next_commitment_nonce")),
        revocationNonce: readNonce(at("revocation_nonce")),
        channelAnnouncementNonce: readOption(at("channel_announcement_nonce"), readNonce),
    };
}

function sameCellDep(a: CellDep, b: CellDep): boolean {
    return equalBytes(a.outPoint.txHash, b.outPoint.txHash) && a.outPoint.index === b.outPoint.index && a.depType === b.depType;
}

// Serde's `Option`: absent or `null` is `None`.
function readOption<Value>(field: WireField, read: (field: WireField) => Value): Value | null {
    return field.value === undefined || field.value === null ? null : read(field);
}

// Serde writes a struct's members in declaration order, so two requests compare alike whatever order their JSON members came in.
// Fiber's conversion reads absent, null and empty `funding_lock_script_cell_deps` as one empty list (`rpc/channel.rs:1130-1136`).
function openCommandOf(params: unknown): unknown {
    if (typeof params !== "object" || params === null) return params;
    return Object.fromEntries(
        Object.entries(params).filter(
            ([name, value]) => name !== "funding_lock_script_cell_deps" || (Array.isArray(value) && value.length > 0),
        ),
    );
}

function canonicalJson(value: unknown): string {
    return JSON.stringify(value, (_key: string, member: unknown): unknown =>
        typeof member === "object" && member !== null && !Array.isArray(member)
            ? Object.fromEntries(Object.entries(member).sort(([a], [b]) => (a < b ? -1 : 1)))
            : member,
    );
}

// Fiber compares receipts whole: the request id, the partial signature and the material.
function receiptOf(submission: Submission): string {
    const material = submission.nextMaterial;
    const hex = (bytes: Uint8Array | null): string => (bytes === null ? "-" : bytesToHex(bytes));
    const parts = [submission.requestId, bytesToHex(submission.partialSignature)];
    if (material !== null) parts.push(hex(material.point), hex(material.commitmentNonce), hex(material.revocationNonce));
    return parts.join(":");
}
