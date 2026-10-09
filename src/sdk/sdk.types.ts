import type { ScriptTemplate } from "../common";
import type { InvoiceCurrency } from "../invoice";
import type { IAsyncSignerStorage, ISignerStorage, PolicyEngine } from "../policy";
import type { FiberRpcClient, IFetchLike, RpcChannelStateName, RpcInvoiceStatus, RpcPaymentStatus } from "../rpc";
import type { ITimer, SessionOptions, SessionState, SignerSession, WebSocketFactory } from "../session";
import type { SignerDispatch } from "../signer";
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
};

/**
 * A chain by name, or by its two constants for a development chain.
 */
export type SdkNetwork = SdkNetworkName | SdkNetworkConfig;

/**
 * The session's timings; its backoff jitter stays `Math.random`, since no RNG is injected.
 */
export type SdkSessionOptions = Pick<SessionOptions, "connectTimeoutMs" | "heartbeatIntervalMs" | "heartbeatTimeoutMs" | "reconnect">;

export type FiberLspSdkOptions = {
    network: SdkNetwork;
    storage: ISignerStorage | IAsyncSignerStorage;
    webSocketFactory: WebSocketFactory;
    rpcUrl: string;
    signerSessionUrl: string;
    /**
     * Omitted when the node's RPC has no auth, as a development chain's may.
     */
    biscuitToken?: string;
    /**
     * The peer every channel opens to, as a compressed point.
     */
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
    session?: SdkSessionOptions;
};

export type SdkEventType = (typeof SDK_EVENT_TYPES)[number];

// Keyed by every event type, so one added to `SDK_EVENT_TYPES` alone fails to compile.
type SdkEventPayloads = {
    SESSION: { state: SessionState };
    CHANNEL_READY: { channelId: string };
    CHANNEL_CLOSED: { channelId: string };
    PAYMENT_SENT: { paymentHashHex: string };
    /**
     * `reason` is fiber's text, verbatim.
     */
    PAYMENT_FAILED: { paymentHashHex: string; reason: string };
    PAYMENT_PENDING: { paymentHashHex: string };
    PAYMENT_RECEIVED: { paymentHashHex: string };
    /**
     * A session error, fatal ones included, or a failed poll step.
     */
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
    session: SignerSession;
    allocator: IndexAllocator;
    activity: ActivityTracker;
    poller: ActivityPoller;
    emit: (event: SdkEvent) => void;
};
