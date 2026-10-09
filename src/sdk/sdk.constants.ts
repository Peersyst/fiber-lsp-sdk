import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../digest";
import { STORAGE_KEY_NAMESPACE } from "../policy";
import type { SdkNetworkConfig, SdkNetworkName } from "./sdk.types";

export const SDK_NETWORK_NAMES = ["mainnet", "testnet"] as const;

export const SDK_NETWORK_PRESETS = {
    mainnet: { commitmentLock: COMMITMENT_LOCK_MAINNET, invoiceCurrency: "Fibb" },
    testnet: { commitmentLock: COMMITMENT_LOCK_TESTNET, invoiceCurrency: "Fibt" },
} as const satisfies Record<SdkNetworkName, SdkNetworkConfig>;

/**
 * Unmeasured against a node: a tick is one `list_channels` plus one read per payment and invoice in flight.
 */
export const DEFAULT_POLL_INTERVAL_MS = 5_000;

/**
 * The default `fetch` has no timeout, so a request that hangs would hold every later tick; far above a node's answer.
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
    "SESSION",
    "CHANNEL_READY",
    "CHANNEL_CLOSED",
    "PAYMENT_SENT",
    "PAYMENT_FAILED",
    "PAYMENT_PENDING",
    "PAYMENT_RECEIVED",
    "ERROR",
] as const;

export const SDK_ERROR_CODES = ["connect_failed", "session_error", "poll_failed", "clock_before_floor"] as const;
