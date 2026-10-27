import { SHANNONS_PER_CKB } from "../common";
import { MAX_COMMITMENT_NUMBER } from "../derivation";
import { MAX_SETTLEMENT_TLCS } from "../digest";

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
 * Pinned to the first value stated; the terms are the host's, and the other pins are fixed at registration.
 */
export const FIRST_SIGHT_CHANNEL_PINS = [
    "fundingOutPoint",
    "fundingCapacityShannons",
    "remoteFundingPubkey",
    "remoteTlcBasePubkey",
    "commitmentDelayEpoch",
    "lockLayout",
] as const;

/**
 * Pinned by the host alone: a message stating one before the host pinned it is refused, never taken as the first sight.
 */
export const CHANNEL_TERMS_PINS = ["liquidCapacityShannons", "commitmentFeeRate", "remoteReservedCkbShannons"] as const;

/**
 * The opening context states three first-sight values beside the terms, so the host may pin them before any request does.
 */
export const HOST_TERMS_PINS = [
    ...CHANNEL_TERMS_PINS,
    "remoteFundingPubkey",
    "remoteTlcBasePubkey",
    "commitmentDelayEpoch",
] as const satisfies readonly ((typeof FIRST_SIGHT_CHANNEL_PINS)[number] | (typeof CHANNEL_TERMS_PINS)[number])[];

export const NONCE_REUSE_MODES = ["refuse", "allow"] as const;

export const SIGNING_LANES = ["COMMITMENT:local", "REVOKE:local", "REVOKE:remote", "ANNOUNCEMENT"] as const;

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
 * The revocation that revokes a version claims the slot one above it, so the chain's last number is never revoked.
 */
export const MAX_REVOKED_VERSION = MAX_COMMITMENT_NUMBER - 1;

/**
 * One spend per TLC and one for the balance, in each of the three commitments a watchtower settles.
 */
export const MAX_WATCHTOWER_SPENDS = 3 * (MAX_SETTLEMENT_TLCS + 1);

/**
 * Fiber's device SDK's bound: its watchtower pays one output, and a second one to the same destination is tolerated.
 */
export const MAX_WATCHTOWER_DESTINATION_OUTPUTS = 2;

/**
 * Stored format: changing it reopens every slot a device has already served.
 */
export const SESSION_COMMITMENT_LABEL = "fiber-lsp-sdk sign-once v1";
