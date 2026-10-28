import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET, FUNDING_LOCK_MAINNET, FUNDING_LOCK_TESTNET } from "../digest";
import { STORAGE_KEY_NAMESPACE } from "../policy";
import type { RpcChannelStateFlag } from "../rpc";
import { RPC_CALL_FAILED_CODE, RPC_PAYMENT_STATUSES } from "../rpc";
import type { SdkNetworkConfig, SdkNetworkName } from "./sdk.types";

export const SDK_NETWORK_NAMES = ["mainnet", "testnet"] as const;

// The cell deps of fiber's funding lock on both presets: the lock's code cell and the auth library's.
const FUNDING_LOCK_CELL_DEPS_COUNT = 2;

// Fiber's `MILLI_SECONDS_PER_EPOCH` in a release build, 4 h, the one public nodes run; a debug build uses 2000.
const RELEASE_MILLISECONDS_PER_EPOCH = 14_400_000;

export const SDK_NETWORK_PRESETS = {
    mainnet: {
        commitmentLock: COMMITMENT_LOCK_MAINNET,
        fundingLock: FUNDING_LOCK_MAINNET,
        invoiceCurrency: "Fibb",
        fundingLockCellDepsCount: FUNDING_LOCK_CELL_DEPS_COUNT,
        millisecondsPerEpoch: RELEASE_MILLISECONDS_PER_EPOCH,
    },
    testnet: {
        commitmentLock: COMMITMENT_LOCK_TESTNET,
        fundingLock: FUNDING_LOCK_TESTNET,
        invoiceCurrency: "Fibt",
        fundingLockCellDepsCount: FUNDING_LOCK_CELL_DEPS_COUNT,
        millisecondsPerEpoch: RELEASE_MILLISECONDS_PER_EPOCH,
    },
} as const satisfies Record<SdkNetworkName, SdkNetworkConfig>;

/**
 * Unmeasured against a node: a tick is one `list_channels`, one read per payment and invoice in flight, one signing status
 * per registered channel and one submit per signature.
 */
export const DEFAULT_POLL_INTERVAL_MS = 5_000;

/**
 * The default `fetch` has no timeout, so a hung request would hold every later tick.
 */
export const POLL_STEP_TIMEOUT_MS = 30_000;

/**
 * 2026-10-01T00:00:00Z: a clock reset to a fixed date is how a wiped device could reuse a second. Set at release, never lowered.
 */
export const ALLOCATION_FLOOR_MS = 1_790_812_800_000;

export const ALLOCATION_KINDS = ["channel", "invoice"] as const;

export const ALLOCATOR_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:allocator:`;

export const ACTIVITY_RECORD_KEY = `${STORAGE_KEY_NAMESPACE}:activity`;

export const ACTIVITY_RECORD_VERSION = 1;

export const ACTIVITY_KINDS = ["channel", "payment", "invoice"] as const;

/**
 * One key, not one per channel: fiber keeps a single opening per tenant.
 */
export const PENDING_OPENING_RECORD_KEY = `${STORAGE_KEY_NAMESPACE}:opening`;

export const PENDING_OPENING_RECORD_VERSION = 1;

/**
 * `stale` is fiber's channel restored from an old database, audited with the peer before it resumes.
 */
export const SDK_CHANNEL_STATES = ["opening", "ready", "closing", "closed", "stale"] as const;

export const SDK_EVENT_TYPES = [
    "CHANNEL_READY",
    "CHANNEL_CLOSED",
    "PAYMENT_SENT",
    "PAYMENT_FAILED",
    "PAYMENT_PENDING",
    "PAYMENT_RECEIVED",
    "PAYMENT_EXPIRED",
    "SIGNING",
    "WATCHTOWER_SIGNING",
    "ERROR",
] as const;

/**
 * Fiber deletes the watch row on a cooperative close and on a failed opening, which may hold one since TxComplete: others are polled.
 */
export const WATCHTOWER_UNWATCHED_CLOSE_FLAGS = [
    "COOPERATIVE",
    "ABANDONED",
    "FUNDING_ABORTED",
] as const satisfies readonly RpcChannelStateFlag<"Closed">[];

/**
 * Fiber's answer while no watch row exists, which `RemoteTxComplete` creates (`rpc/watchtower.rs:386-391`, `event_handler.rs:41-67`).
 */
export const WATCHTOWER_UNWATCHED_ERROR = { code: RPC_CALL_FAILED_CODE, message: "watched channel not found" } as const;

/**
 * Fiber's answer to `settle_invoice` once the fulfil is applied (`fiber/network.rs:4854`, `rpc/utils.rs:90-131`): the settlement is done.
 */
export const SDK_INVOICE_ALREADY_PAID_ERROR = { code: RPC_CALL_FAILED_CODE, message: "Invoice is already paid" } as const;

/**
 * Where fiber's external funding puts the channel's cell in the funding tx it freezes.
 */
export const FUNDING_OUTPUT_INDEX = 0;

/**
 * Fiber's default, one epoch, sent rather than left to the node so the answer is checked against a known value.
 */
export const DEFAULT_COMMITMENT_DELAY_EPOCH = 0x10000000001n;

/**
 * Fiber's default, in shannons per kilobyte, sent for the same reason as the delay.
 */
export const DEFAULT_COMMITMENT_FEE_RATE = 1000n;

export const SDK_ERROR_CODES = [
    "poll_failed",
    "clock_before_floor",
    "unknown_channel",
    "opening_rejected",
    "opening_conflict",
    "funding_tx_altered",
    "invoice_rejected",
    "invoice_unpayable",
    "payment_in_flight",
    "payment_charged",
    "own_invoice",
    "close_fee_too_high",
] as const;

/**
 * Fiber has no default, and a tenant's invoice without an expiry fails after its row is stored.
 */
export const DEFAULT_SDK_INVOICE_EXPIRY_SECONDS = 3600n;

/**
 * Fiber's `DEFAULT_FINAL_TLC_EXPIRY_DELTA`; `new_invoice`'s own default, two thirds of an epoch, leaves a held TLC no margin to release.
 */
export const SDK_INVOICE_FINAL_EXPIRY_DELTA_MS = 86_400_000n;

/**
 * How far ahead of the device's clock the node's invoice timestamp may be: fiber counts the expiry from it.
 */
export const SDK_INVOICE_TIMESTAMP_SKEW_MS = 600_000n;

/**
 * Past fiber's 60 s channel check, the time the poller takes to sign the fulfil before the node would fail the held TLC.
 */
export const SDK_RELEASE_EXPIRY_SLACK_MS = 600_000n;

/**
 * Fiber's `get_payment` answer for a hash with no session, followed by `Hash256(0x…)` (`fiber/network.rs:5455-5462`,
 * `primitives.rs:358-369`): the send never ran.
 */
export const SDK_PAYMENT_NOT_FOUND_ERROR = {
    code: RPC_CALL_FAILED_CODE,
    messagePrefix: "InvalidParameter: Payment session not found: ",
    messageSuffix: "",
} as const;

export const SDK_PAYMENT_NEVER_SENT_REASON = "the node holds no session of the payment: it was never sent";

export const SDK_PAYMENT_UNEXPLAINED_FAILURE_REASON = "the node reports the payment failed without a reason";

/**
 * Fiber's `DEFAULT_MAX_FEE_RATE` (`fiber/payment.rs:50`), which caps a payment's fees whatever the host asks.
 */
export const DEFAULT_SDK_MAX_FEE_PER_MILLE = 5n;

/**
 * Fiber's `MAX_FEE_RATE_DENOMINATOR` (`fiber/payment.rs:51`).
 */
export const SDK_MAX_FEE_RATE_DENOMINATOR = 1000n;

/**
 * Fiber's answer when the actor dropped its reply (`rpc/utils.rs:112-121`, ractor 0.15.13's `MessagingErr::ChannelClosed`):
 * the call may have run.
 */
export const SDK_ACTOR_REPLY_LOST_ERROR = { code: RPC_CALL_FAILED_CODE, message: "Messaging failed because channel is closed" } as const;

/**
 * Fiber's `send_payment` answers while it holds a session under the hash, each around `Hash256(0x…)`: the actor still
 * running (`fiber/network.rs:5544-5551`), a session not failed, with its Debug status (`fiber/payment.rs:2194-2198`), and a
 * failed one with attempts in flight (`fiber/payment.rs:2204-2208`).
 */
export const SDK_PAYMENT_SESSION_EXISTS_ERRORS = [
    { code: RPC_CALL_FAILED_CODE, messagePrefix: "Payment session already exists, stop start new payment actor for ", messageSuffix: "" },
    ...RPC_PAYMENT_STATUSES.filter((status) => status !== "Failed").map((status) => ({
        code: RPC_CALL_FAILED_CODE,
        messagePrefix: "InvalidParameter: Payment session already exists: ",
        messageSuffix: ` with payment session status: ${status}`,
    })),
    {
        code: RPC_CALL_FAILED_CODE,
        messagePrefix: "InvalidParameter: Payment session ",
        messageSuffix: " has attempts that are in flight state, can not retry",
    },
] as const;

export const SDK_INVOICE_UNPAYABLE = "the invoice cannot be paid";

export const SDK_PAYMENT_REFUSED = "the device refuses the payment";
