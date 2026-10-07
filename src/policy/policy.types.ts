import type { TlcDirection, TlcHashAlgorithm } from "../common";
import type { NonceContext } from "../derivation";
import type { ChannelAnnouncementInput, CommitmentTxInput, RevocationInput, ShutdownTxInput } from "../digest";
import type {
    CHANNEL_POLICY_RECORD_VERSION,
    DEBIT_INTENT_ERROR_CODES,
    FIRST_SIGHT_CHANNEL_PINS,
    HOLD_INVOICE_ERROR_CODES,
    PAYMENT_RECORD_VERSION,
    POLICY_VIEWS,
} from "./policy.constants";

export type DebitIntentErrorCode = (typeof DEBIT_INTENT_ERROR_CODES)[number];

export type HoldInvoiceErrorCode = (typeof HOLD_INVOICE_ERROR_CODES)[number];

export type SignSlot = `${NonceContext}:${number}`;

export type ChannelPolicyRecord = {
    version: typeof CHANNEL_POLICY_RECORD_VERSION;
    /**
     * The channel's current name, which moves when the open handshake fixes it; the record's own key does not.
     */
    channelId: string;
    lastSignedCommitmentNumbers: Partial<Record<NonceContext, number>>;
    /**
     * Sign-once registry: the commitment to the session each slot served, not to its message alone.
     */
    signedSessions: Partial<Record<SignSlot, string>>;
    lastStateVersion: number;
    pins: ChannelPins;
    /**
     * One per commitment: the two may list different TLCs.
     */
    views: Record<PolicyView, PolicyViewSnapshot>;
};

export type FirstSightChannelPin = (typeof FIRST_SIGHT_CHANNEL_PINS)[number];

/**
 * Canonical strings, so pins compare by equality.
 */
export type ChannelPins = {
    /**
     * Reserve included.
     */
    fundedShannons: string;
    /**
     * Molecule hex.
     */
    localCloseScript: string;
    /**
     * Fiber sizes it over `localCloseScript`.
     */
    localReservedCkbShannons: string;
    /**
     * CKB channels only, until the multi-asset shape is decided.
     */
    udtTypeScript: null;
} & Partial<Record<FirstSightChannelPin, string>>;

export type StatedChannelPins = Partial<Record<FirstSightChannelPin | "localCloseScript" | "localReservedCkbShannons", string>> & {
    udtTypeScript?: string | null;
};

export type ChannelPinConflict = {
    field: keyof StatedChannelPins;
    pinned: string | null;
    stated: string | null;
};

/**
 * `remote` is the peer's commitment (fiber's `forRemote`), `local` the device's own.
 */
export type PolicyView = (typeof POLICY_VIEWS)[number];

/**
 * A TLC as the settlement witness binds it.
 */
export type PolicyViewTlc = {
    direction: TlcDirection;
    hashAlgorithm: TlcHashAlgorithm;
    /**
     * First 20 bytes of the payment hash, lowercase hex.
     */
    boundPaymentHash: string;
    amountShannons: string;
    expirySeconds: string;
};

/**
 * One view's state after its last signed message.
 */
export type PolicyViewSnapshot = {
    /**
     * Fiber's TLC-adjusted settlement amount plus the reserve, not the raw balance, in decimal shannons.
     */
    exposureShannons: string;
    tlcs: PolicyViewTlc[];
    /**
     * Per bound payment hash, what offered TLCs that left this view took.
     */
    chargedShannons: Record<string, string>;
    /**
     * Per bound payment hash, what received TLCs of a released invoice paid this view.
     */
    creditedShannons: Record<string, string>;
};

/**
 * A user-approved budget for one payment, shared across channels.
 */
export type DebitIntentRecord = {
    version: typeof PAYMENT_RECORD_VERSION;
    /**
     * Lowercase hex; the record is keyed by its first 20 bytes.
     */
    paymentHash: string;
    /**
     * Amount plus fee budget.
     */
    maxShannons: string;
    /**
     * Closing stops growth only: TLCs already shown stay signable.
     */
    open: boolean;
    /**
     * Channels that have shown a TLC under the hash, filed before the claim that shows it.
     */
    channelIndexes: number[];
};

/**
 * An invoice whose preimage the device holds.
 */
export type HoldInvoicePolicyRecord = {
    version: typeof PAYMENT_RECORD_VERSION;
    /**
     * Lowercase hex; the record is keyed by its first 20 bytes.
     */
    paymentHash: string;
    amountShannons: string;
    /**
     * A TLC under another algorithm is not this invoice's.
     */
    hashAlgorithm: TlcHashAlgorithm;
    released: boolean;
    /**
     * Channels that have shown a TLC under the hash, filed before the claim that shows it.
     */
    channelIndexes: number[];
};

export type SignSession = {
    /**
     * The 2-of-2 key list exactly as the node sent it; the SDK never sorts or reorders it.
     */
    orderedPublicKeys: Uint8Array[];
    aggregatedNonce: Uint8Array;
    /**
     * Opaque to the engine until the policy layer recomputes it.
     */
    message: Uint8Array;
};

export type SignOperation =
    | { kind: "commitment_tx"; input: CommitmentTxInput }
    | { kind: "shutdown_tx"; input: ShutdownTxInput }
    | { kind: "revocation"; input: RevocationInput }
    | { kind: "channel_announcement"; input: ChannelAnnouncementInput };

export type SignOperationKind = SignOperation["kind"];

export type PolicySignRequest = {
    channelId: string;
    stateVersion: number;
    /**
     * The number the nonce slot is keyed by, which is not always the number inside the message; absent for the
     * announcement, whose slot `resolveSignSlot` fixes.
     */
    nonceCommitmentNumber?: number;
    session: SignSession;
    operation: SignOperation;
};

export type SignSlotRef = {
    context: NonceContext;
    commitmentNumber: number;
};

export type PolicyVerdict = SignSlotRef & {
    status: "fresh" | "already-signed";
};

export type BalanceRuleCommitment = {
    exposureShannons: bigint;
    tlcs: PolicyViewTlc[];
};

/**
 * The device-wide records the balance rule reads.
 */
export type BalanceRuleContext = {
    /**
     * Keyed by bound payment hash.
     */
    intents: ReadonlyMap<string, DebitIntentRecord>;
    /**
     * Keyed by bound payment hash.
     */
    invoices: ReadonlyMap<string, HoldInvoicePolicyRecord>;
    /**
     * Both views: the node may broadcast either commitment.
     */
    otherChannels: readonly Record<PolicyView, PolicyViewSnapshot>[];
};
