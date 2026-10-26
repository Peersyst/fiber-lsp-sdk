import type { ITimer, ScriptTemplate } from "../common";
import type { InvoiceCurrency } from "../invoice";
import type {
    IAsyncSignerStorage,
    ISignerStorage,
    NonceReuseMode,
    PolicyEngine,
    WatchtowerApproval,
    WatchtowerKeyPurpose,
} from "../policy";
import type { ChannelSigningTransition } from "../protocol";
import type { FiberRpcClient, IFetchLike, RpcChannelStateName, RpcInvoiceStatus, RpcPaymentStatus } from "../rpc";
import type { SignerDispatch, SignerRefusal } from "../signer";
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

export type SdkContext = {
    network: SdkNetworkConfig;
    lspPubkey: Uint8Array;
    now: () => number;
    rpc: FiberRpcClient;
    policy: PolicyEngine;
    dispatch: SignerDispatch;
    allocator: IndexAllocator;
    activity: ActivityTracker;
    poller: ActivityPoller;
    emit: (event: SdkEvent) => void;
};
