import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../digest";
import { STORAGE_KEY_NAMESPACE } from "../policy";
import type { RpcChannelStateFlag } from "../rpc";
import { RPC_CALL_FAILED_CODE } from "../rpc";
import type { SdkNetworkConfig, SdkNetworkName } from "./sdk.types";

export const SDK_NETWORK_NAMES = ["mainnet", "testnet"] as const;

// The cell deps of fiber's funding lock on both presets: the lock's code cell and the auth library's.
const FUNDING_LOCK_CELL_DEPS_COUNT = 2;

export const SDK_NETWORK_PRESETS = {
    mainnet: { commitmentLock: COMMITMENT_LOCK_MAINNET, invoiceCurrency: "Fibb", fundingLockCellDepsCount: FUNDING_LOCK_CELL_DEPS_COUNT },
    testnet: { commitmentLock: COMMITMENT_LOCK_TESTNET, invoiceCurrency: "Fibt", fundingLockCellDepsCount: FUNDING_LOCK_CELL_DEPS_COUNT },
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

export const SDK_EVENT_TYPES = [
    "CHANNEL_READY",
    "CHANNEL_CLOSED",
    "PAYMENT_SENT",
    "PAYMENT_FAILED",
    "PAYMENT_PENDING",
    "PAYMENT_RECEIVED",
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

export const SDK_ERROR_CODES = ["poll_failed", "clock_before_floor"] as const;
