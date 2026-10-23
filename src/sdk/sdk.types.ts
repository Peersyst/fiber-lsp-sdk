import type { ITimer, ScriptTemplate } from "../common";
import type { InvoiceCurrency } from "../invoice";
import type {
    IAsyncSignerStorage,
    ISignerStorage,
    NonceReuseMode,
    PolicyEngine,
    SignerStore,
    WatchtowerApproval,
    WatchtowerKeyPurpose,
} from "../policy";
import type { ChannelSigningTransition } from "../protocol";
import type {
    FiberRpcClient,
    GetTenantRegistryNonceResult,
    IFetchLike,
    RegisterTenantParams,
    RpcChannelStateName,
    RpcInvoiceStatus,
    RpcPaymentStatus,
} from "../rpc";
import type { SignerDispatch, SignerRefusal, TenantIdentity } from "../signer";
import type { ActivityTracker } from "./activity";
import type { IndexAllocator } from "./allocator";
import type { ActivityPoller } from "./poller";
import type {
    ACTIVITY_KINDS,
    ACTIVITY_RECORD_VERSION,
    ALLOCATION_KINDS,
    SDK_ERROR_CODES,
    SDK_EVENT_TYPES,
    SDK_NETWORK_NAMES,
} from "./sdk.constants";
import type { SdkError } from "./sdk.error";

export type SdkNetworkName = (typeof SDK_NETWORK_NAMES)[number];

export type SdkNetworkConfig = {
    commitmentLock: ScriptTemplate;
    invoiceCurrency: InvoiceCurrency;
    /**
     * Fiber counts these into the commitment fee although the commitment tx carries none.
     */
    fundingLockCellDepsCount: number;
    /**
     * Fiber's `MILLI_SECONDS_PER_EPOCH`, which the node's build sets: 4 h in release, 2 s in debug.
     */
    millisecondsPerEpoch: number;
};

export type SdkNetwork = SdkNetworkName | SdkNetworkConfig;

export type SdkWatchtowerOptions = WatchtowerApproval;

export type FiberLspSdkOptions = {
    network: SdkNetwork;
    storage: ISignerStorage | IAsyncSignerStorage;
    rpcUrl: string;
    /**
     * Omitted when the node's RPC has no auth, as a development chain's may.
     */
    biscuitToken?: string;
    lspPubkey: Uint8Array;
    /**
     * Defaults to the runtime's global `fetch`.
     */
    fetch?: IFetchLike;
    /**
     * Defaults to the runtime's `setTimeout` and `clearTimeout`, read once at construction.
     */
    timer?: ITimer;
    /**
     * Milliseconds since the epoch; defaults to `Date.now`.
     */
    now?: () => number;
    pollIntervalMs?: number;
    /**
     * Defaults to `refuse`; `allow` serves a second signing session on a slot, as fiber's nonce lifecycle asks, never a third.
     */
    nonceReuse?: NonceReuseMode;
    /**
     * Without it, every spend the node's watchtower asks the device to sign is refused.
     */
    watchtower?: SdkWatchtowerOptions;
};

export type SdkEventType = (typeof SDK_EVENT_TYPES)[number];

/**
 * `warning`: a signature served under `nonceReuse: "allow"` on a slot that already served another session.
 */
export type SigningEventOutcome = "signed" | "warning" | "refused";

type SigningEventPayload = {
    channelId: string;
    /**
     * Wire hex; `null`, with the transition, when the status could not be read or was another channel's.
     */
    requestId: string | null;
    transition: ChannelSigningTransition | null;
    /**
     * When fiber force-closes the channel still awaiting the signature, in ms since the epoch. An upper bound, over the node's
     * unchecked expiries on a refusal. Absent when the device cannot compute it (no TLC, no pinned delay, a failed pin read),
     * not when fiber has none.
     */
    deadlineMs?: number;
} & ({ outcome: Exclude<SigningEventOutcome, "refused"> } | { outcome: "refused"; error: SignerRefusal });

type WatchtowerSigningEventPayload = {
    channelId: string;
    /**
     * Wire hex; `null`, with the purpose, when the status could not be read or was another channel's.
     */
    requestId: string | null;
    purpose: WatchtowerKeyPurpose | null;
} & ({ outcome: "signed" } | { outcome: "refused"; error: SignerRefusal });

// Keyed by every event type, so one added to `SDK_EVENT_TYPES` alone fails to compile.
type SdkEventPayloads = {
    CHANNEL_READY: { channelId: string };
    CHANNEL_CLOSED: { channelId: string };
    PAYMENT_SENT: { paymentHashHex: string };
    /**
     * `reason` is fiber's text, verbatim.
     */
    PAYMENT_FAILED: { paymentHashHex: string; reason: string };
    PAYMENT_PENDING: { paymentHashHex: string };
    PAYMENT_RECEIVED: { paymentHashHex: string };
    SIGNING: SigningEventPayload;
    WATCHTOWER_SIGNING: WatchtowerSigningEventPayload;
    ERROR: { error: SdkError };
};

export type SdkEvent = { [Type in SdkEventType]: { type: Type } & SdkEventPayloads[Type] }[SdkEventType];

export type SdkEventListener = (event: SdkEvent) => void;

export type SdkErrorCode = (typeof SDK_ERROR_CODES)[number];

export type AllocationKind = (typeof ALLOCATION_KINDS)[number];

export type ActivityKind = (typeof ACTIVITY_KINDS)[number];

export type ActivityStatus<Kind extends ActivityKind> = {
    channel: RpcChannelStateName;
    payment: RpcPaymentStatus;
    invoice: RpcInvoiceStatus;
}[Kind];

export type ActivityEntry<Kind extends ActivityKind> = {
    /**
     * The last status an event was emitted for; `null` until the first.
     */
    status: ActivityStatus<Kind> | null;
};

export type ActivityRecord = {
    version: typeof ACTIVITY_RECORD_VERSION;
    channels: Record<string, ActivityEntry<"channel">>;
    payments: Record<string, ActivityEntry<"payment">>;
    invoices: Record<string, ActivityEntry<"invoice">>;
};

export type SdkTenantChallenge = GetTenantRegistryNonceResult;

export type SdkTenantRegistration = RegisterTenantParams & { tenantId: string };

type CommitmentEvidence = { commitmentNumber: number; txHash: string };

/**
 * Every hex value is `0x`-prefixed lowercase, as fiber's JSON writes it.
 */
export type SdkChannelEvidence = {
    /**
     * Ascending by version.
     */
    revocations: { version: number; forRemote: boolean; signature: string }[];
    /**
     * The last commitment signed in each view; `txHash` is fiber's `compute_tx_message`, not the hash the chain shows.
     */
    commitments: { local: CommitmentEvidence | null; remote: CommitmentEvidence | null };
    /**
     * In claim order; `applied` once fiber took the signature.
     */
    watchtowerSignatures: { requestId: string; purpose: WatchtowerKeyPurpose; signature: string; applied: boolean }[];
};

export type SdkContext = {
    network: SdkNetworkConfig;
    lspPubkey: Uint8Array;
    now: () => number;
    store: SignerStore;
    identity: TenantIdentity;
    rpc: FiberRpcClient;
    policy: PolicyEngine;
    dispatch: SignerDispatch;
    allocator: IndexAllocator;
    activity: ActivityTracker;
    poller: ActivityPoller;
    emit: (event: SdkEvent) => void;
};
