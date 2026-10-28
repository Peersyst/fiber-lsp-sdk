import type { DepType, ITimer, Script, ScriptTemplate, Transaction } from "../common";
import type { InvoiceCurrency } from "../invoice";
import type {
    IAsyncSignerStorage,
    ISignerStorage,
    NonceReuseMode,
    PolicyChannelTerms,
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
    NewInvoiceParams,
    RegisterTenantParams,
    RpcChannelStateName,
    RpcInvoiceStatus,
    RpcPaymentStatus,
    TenantChannelOpeningContext,
} from "../rpc";
import type { HoldInvoicePreimages, SignerDispatch, SignerRefusal, TenantIdentity } from "../signer";
import type { ActivityTracker } from "./activity";
import type { IndexAllocator } from "./allocator";
import type { PendingOpeningStore } from "./pending-opening";
import type { ActivityPoller } from "./poller";
import type {
    ACTIVITY_KINDS,
    ACTIVITY_RECORD_VERSION,
    ALLOCATION_KINDS,
    PENDING_OPENING_RECORD_VERSION,
    SDK_CHANNEL_STATES,
    SDK_ERROR_CODES,
    SDK_EVENT_TYPES,
    SDK_NETWORK_NAMES,
} from "./sdk.constants";
import type { SdkError } from "./sdk.error";

export type SdkNetworkName = (typeof SDK_NETWORK_NAMES)[number];

export type SdkNetworkConfig = {
    commitmentLock: ScriptTemplate;
    /**
     * Its args are the channel's own, computed from the two funding keys.
     */
    fundingLock: ScriptTemplate;
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
     * `reason` is fiber's `failed_error`, verbatim, or the SDK's own when the node never ran the send or gave none.
     */
    PAYMENT_FAILED: { paymentHashHex: string; reason: string };
    PAYMENT_PENDING: { paymentHashHex: string };
    PAYMENT_RECEIVED: { paymentHashHex: string };
    /**
     * Ended unpaid, its preimage never released: fiber expired or cancelled it, or it is past its expiry with no TLC of it left.
     */
    PAYMENT_EXPIRED: { paymentHashHex: string };
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

export type PendingOpening = {
    channelIndex: number;
    /**
     * Reserve included.
     */
    fundedShannons: string;
    /**
     * Molecule hex, so a retry compares it by equality.
     */
    userLock: string;
    userLockCellDeps?: PendingOpeningCellDep[];
    /**
     * `null` until the node's answer passes the check.
     */
    channelId: string | null;
};

/**
 * The tx hash in lowercase hex without the prefix, as the store keeps bytes.
 */
export type PendingOpeningCellDep = { txHash: string; index: number; depType: DepType };

/**
 * The storage has no delete, so a cleared opening is `null` rather than an absent key.
 */
export type PendingOpeningRecord = {
    version: typeof PENDING_OPENING_RECORD_VERSION;
    opening: PendingOpening | null;
};

export type SdkChannelState = (typeof SDK_CHANNEL_STATES)[number];

export type SdkChannelInfo = {
    channelId: string;
    state: SdkChannelState;
    localBalanceShannons: string;
    remoteBalanceShannons: string;
    offeredTlcBalanceShannons: string;
    receivedTlcBalanceShannons: string;
    /**
     * Whether this device registered the channel.
     */
    hasRecord: boolean;
};

/**
 * Copies: nothing the device keeps changes with them.
 */
export type SdkChannelOpening = {
    channelId: string;
    unsignedFundingTx: Transaction;
    openingContext: TenantChannelOpeningContext;
};

/**
 * The host's signer, which resolves the inputs and so is the one to check what they pay before signing.
 */
export type SdkSignFundingInputs = (unsignedFundingTx: Transaction) => Promise<Transaction>;

export type SdkOpeningRequest = {
    /**
     * Reserve included.
     */
    fundedShannons: string;
    userLock: Script;
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    /**
     * The device's own.
     */
    fundingPubkey: Uint8Array;
    tlcBasePubkey: Uint8Array;
    fundingLock: ScriptTemplate;
};

export type SdkOpeningPins = {
    terms: PolicyChannelTerms;
    fundingCapacityShannons: string;
};

export type SdkInvoiceOptions = {
    /**
     * At most 639 bytes of well-formed UTF-8, fiber's bound.
     */
    description?: string;
    /**
     * Whole seconds; defaults to one hour.
     */
    expirySeconds?: number;
};

export type SdkInvoice = {
    /**
     * The node's string, checked: the one to show the payer.
     */
    invoice: string;
    /**
     * `0x`-prefixed lowercase hex, as the events carry it.
     */
    paymentHashHex: string;
};

/**
 * What the device sent `new_invoice`, and the LSP's key, which fiber writes as a tenant's trampoline hint.
 */
export type SdkInvoiceRequest = NewInvoiceParams & { lspPubkey: Uint8Array };

export type SdkTransferOptions = {
    /**
     * Decimal shannons, 0 allowed; defaults to fiber's 0.5% of the amount, rounded up, which is also fiber's cap.
     * Under trampoline, to any payee but the LSP, a budget below `ceil(amount / 1000)` fails the route.
     */
    maxFeeShannons?: string;
};

export type SdkCloseOptions = {
    /**
     * The device's own, in shannons per kilobyte; defaults to the channel's commitment fee rate, which fiber refuses to go below.
     */
    feeRate?: bigint;
};

export type SdkPayment = {
    /**
     * `0x`-prefixed lowercase hex, as the events carry it.
     */
    paymentHashHex: string;
    amountShannons: string;
    /**
     * The fee budget sent, which the debit intent approves with the amount.
     */
    maxFeeShannons: string;
};

export type SdkPayableInvoice = { paymentHash: Uint8Array; amountShannons: string; payeePublicKey: Uint8Array };

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
    preimages: HoldInvoicePreimages;
    rpc: FiberRpcClient;
    policy: PolicyEngine;
    dispatch: SignerDispatch;
    allocator: IndexAllocator;
    activity: ActivityTracker;
    openings: PendingOpeningStore;
    poller: ActivityPoller;
    /**
     * Payment hashes, lowercase hex, whose `transfer` runs in this instance, which the payment step skips. In memory only:
     * after a crash the step resolves what the call left watched.
     */
    sending: Set<string>;
    /**
     * Payment hashes, lowercase hex, whose answer the payment step is acting on, which `transfer` refuses, so the step never
     * ends a payment on an answer older than a retry's send.
     */
    reading: Set<string>;
    emit: (event: SdkEvent) => void;
};
