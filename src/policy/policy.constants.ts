import { SHANNONS_PER_CKB } from "../common";

/**
 * Namespaced: the host may back the storage with a store it also uses for its own keys.
 */
export const STORAGE_KEY_NAMESPACE = "fiber-lsp-sdk";

/**
 * Keyed by channel index, the one name a channel never changes: everything a record protects derives from that index.
 */
export const CHANNEL_RECORD_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:channel:`;

/**
 * Channel id to channel index, many to one: fiber renames a channel when the open handshake fixes its id.
 */
export const CHANNEL_ALIAS_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:alias:`;
export const HOLD_INVOICE_PREIMAGE_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:preimage:`;

export const DEBIT_INTENT_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:intent:`;

export const HOLD_INVOICE_RECORD_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:invoice:`;

/**
 * A serialization lane, never a stored key.
 */
export const BALANCE_LANE_KEY = `${STORAGE_KEY_NAMESPACE}:balance`;

export const POLICY_VIEWS = ["remote", "local"] as const;

export const DEBIT_INTENT_ERROR_CODES = ["intent_open", "intent_charged", "own_invoice"] as const;

export const HOLD_INVOICE_ERROR_CODES = ["offered_in_flight", "algorithm_mismatch"] as const;

/**
 * Pinned to the first value stated; the other pins are fixed at registration.
 */
export const FIRST_SIGHT_CHANNEL_PINS = [
    "fundingOutPoint",
    "fundingCapacityShannons",
    "liquidCapacityShannons",
    "remoteFundingPubkey",
    "remoteTlcBasePubkey",
    "commitmentDelayEpoch",
    "commitmentFeeRate",
    "remoteReservedCkbShannons",
] as const;

/**
 * Fiber's `DEFAULT_MIN_SHUTDOWN_FEE`.
 */
export const RESERVED_SHUTDOWN_FEE_SHANNONS = SHANNONS_PER_CKB;

/**
 * Stricter than fiber, which bounds the close fee by the balance.
 */
export const MAX_SHUTDOWN_FEE_SHANNONS = RESERVED_SHUTDOWN_FEE_SHANNONS;

/**
 * Fiber's `check_commitment_reserved_fee`, rechecked because the node supplies the rate.
 */
export const MAX_COMMITMENT_FEE_SHANNONS = RESERVED_SHUTDOWN_FEE_SHANNONS / 2n;

export const SHANNONS_PER_OCCUPIED_BYTE = SHANNONS_PER_CKB;

/**
 * Past this many offered TLCs leaving at once, all are charged: the exact search is exponential.
 */
export const MAX_EXACT_CHARGE_TLCS = 12;

/**
 * Bumped on format changes so old records migrate instead of being rejected: a rejected record loses its sign-once registry.
 */
export const CHANNEL_POLICY_RECORD_VERSION = 1;

export const PAYMENT_RECORD_VERSION = 1;

/**
 * The announcement nonce never rotates, so its slot is fixed and latched on first use.
 */
export const ANNOUNCEMENT_SLOT_NUMBER = 0;

/**
 * Stored format: changing it reopens every slot a device has already served.
 */
export const SESSION_COMMITMENT_LABEL = "fiber-lsp-sdk sign-once v1";
