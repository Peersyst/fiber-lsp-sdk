import type { TlcDirection, TlcHashAlgorithm } from "../common";
import type { NonceContext } from "../derivation";
import type { ChannelAnnouncementInput, ClosingTxInput, CommitmentLockLayout, CommitmentTxInput, RevocationInput } from "../digest";
import type {
    CHANNEL_POLICY_RECORD_VERSION,
    CHANNEL_TERMS_PINS,
    DEBIT_INTENT_ERROR_CODES,
    FIRST_SIGHT_CHANNEL_PINS,
    HOLD_INVOICE_ERROR_CODES,
    NONCE_REUSE_MODES,
    PAYMENT_RECORD_VERSION,
    POLICY_VIEWS,
    SIGNING_LANES,
} from "./policy.constants";

export type DebitIntentErrorCode = (typeof DEBIT_INTENT_ERROR_CODES)[number];

export type HoldInvoiceErrorCode = (typeof HOLD_INVOICE_ERROR_CODES)[number];

export type SignSlot = `${NonceContext}:${number}`;

export type NonceReuseMode = (typeof NONCE_REUSE_MODES)[number];

export type NonceCounter = "local" | "remote";

/**
 * One monotonic sequence per fiber counter: the two revocation lanes advance on different events.
 */
export type SigningLane = (typeof SIGNING_LANES)[number];

/**
 * The last commitment signed in a view: its version floor, and the replacement a revocation needs.
 */
export type SignedCommitmentRecord = {
    commitmentNumber: number;
    /**
     * Fiber's `compute_tx_message` of the tx as signed, lowercase hex: not the on-chain hash, since the tx fiber broadcasts
     * adds the funding lock's cell deps.
     */
    txHash: string;
};

export type RevocationEvidence = {
    version: number;
    forRemote: true;
    /**
     * Aggregated schnorr signature, lowercase hex.
     */
    signature: string;
};

/**
 * A session `allow` served on a slot after its first; at most one per slot, since a third session solves for the funding key.
 */
export type NonceReuseEntry = {
    sessionCommitment: string;
    /**
     * Lowercase hex.
     */
    message: string;
};

export type ChannelPolicyRecord = {
    version: typeof CHANNEL_POLICY_RECORD_VERSION;
    /**
     * The channel's current name, which moves when the open handshake fixes it; the record's own key does not.
     */
    channelId: string;
    lastSignedCommitmentNumbers: Partial<Record<SigningLane, number>>;
    /**
     * Sign-once registry: the commitment to the session each slot served, not to its message alone.
     */
    signedSessions: Partial<Record<SignSlot, string>>;
    /**
     * Written under `allow` only, so a sweep of the store shows what the permissive mode let through.
     */
    nonceReuse: Partial<Record<SignSlot, NonceReuseEntry>>;
    commitmentHashes: Partial<Record<PolicyView, SignedCommitmentRecord>>;
    /**
     * Ascending by version, upserted by version.
     */
    revocations: RevocationEvidence[];
    pins: ChannelPins;
    /**
     * One per commitment: the two may list different TLCs.
     */
    views: Record<PolicyView, PolicyViewSnapshot>;
};

export type FirstSightChannelPin = (typeof FIRST_SIGHT_CHANNEL_PINS)[number];

export type ChannelTermsPin = (typeof CHANNEL_TERMS_PINS)[number];

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
     * One per layout, since fiber counts the close script's args at no less than the lock's; the pinned `lockLayout` picks.
     */
    localReservedCkbShannons: Record<CommitmentLockLayout, string>;
    /**
     * CKB channels only, until the multi-asset shape is decided.
     */
    udtTypeScript: null;
} & Partial<Record<FirstSightChannelPin | ChannelTermsPin, string>>;

export type StatedChannelPins = Partial<
    Record<FirstSightChannelPin | ChannelTermsPin | "localCloseScript" | "localReservedCkbShannons", string>
> & {
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
     * First 20 bytes, lowercase hex: the key of the payment records under both layouts, and all a `legacy` witness binds.
     */
    boundPaymentHash: string;
    /**
     * The whole 32-byte hash, lowercase hex, when the layout binds it; `null` under `legacy`.
     */
    fullPaymentHash: string | null;
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

export type SignerRecordFormat<T> = {
    name: string;
    is: (value: unknown) => value is T;
    assert: (name: string, value: unknown) => asserts value is T;
    belongsAt: (key: string, record: T) => boolean;
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
    | { kind: "closing_tx"; input: ClosingTxInput }
    | { kind: "revocation"; input: RevocationInput }
    | { kind: "channel_announcement"; input: ChannelAnnouncementInput };

export type SignOperationKind = SignOperation["kind"];

export type PolicySignRequest = {
    channelId: string;
    /**
     * Not always the number inside the message; the context follows from the operation.
     */
    slot: { commitmentNumber: number; counter: NonceCounter | null };
    session: SignSession;
    operation: SignOperation;
};

export type SignSlotRef = {
    context: NonceContext;
    commitmentNumber: number;
};

export type SignSlotClaim = SignSlotRef & {
    lane: SigningLane;
};

export type PolicyVerdict = SignSlotRef & {
    status: "fresh" | "already-signed" | "reused";
};

export type PolicyEngineOptions = {
    /**
     * `refuse` unless set.
     */
    nonceReuse?: NonceReuseMode;
};

/**
 * The terms no signing request states, pinned by the host from the node's `opening_context`.
 */
export type PolicyChannelTerms = {
    commitmentFeeRate: bigint;
    remoteReservedCkbShannons: string;
    liquidCapacityShannons: string;
};

export type RevokedCommitmentSignature = {
    version: number;
    signature: Uint8Array;
};

export type BalanceRuleCommitment = {
    exposureShannons: bigint;
    tlcs: PolicyViewTlc[];
};

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
