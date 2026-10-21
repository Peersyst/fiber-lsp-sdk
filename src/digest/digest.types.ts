import type { OutPoint, Script, ScriptTemplate, TlcDirection, TlcHashAlgorithm } from "../common";
import type { COMMITMENT_LOCK_LAYOUTS } from "./digest.constants";

export type CommitmentLockLayout = (typeof COMMITMENT_LOCK_LAYOUTS)[number];

/**
 * Selection and status filtering happen node-side: the signature only binds to the set the device was shown.
 */
export type SettlementTlc = {
    /**
     * The witness sort key.
     */
    id: number;
    /**
     * From the device's side, before any `forRemote` flip.
     */
    direction: TlcDirection;
    hashAlgorithm: TlcHashAlgorithm;
    amountShannons: bigint;
    paymentHash: Uint8Array;
    /**
     * The witness truncates it to whole seconds.
     */
    expiryMs: bigint;
    /**
     * Fiber's `local_key_commitment_number`.
     */
    localKeyCommitmentNumber: number;
    /**
     * Derived node-side from the peer's commitment point; hashed as it comes.
     */
    remoteTlcPubkey: Uint8Array;
};

export type CommitmentTxInput = {
    /**
     * `true` builds the tx the device signs into its outgoing `commitment_signed`.
     */
    forRemote: boolean;
    fundingOutPoint: OutPoint;
    remoteFundingPubkey: Uint8Array;
    remoteTlcBasePubkey: Uint8Array;
    /**
     * The lock args version: the local commitment number when `forRemote`, the remote one otherwise.
     */
    commitmentNumber: number;
    /**
     * The full `EpochNumberWithFraction` value.
     */
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    /**
     * Mocked into fee sizing even though the digest blanks the cell deps.
     */
    cellDepsCount: number;
    udtTypeScript: Script | null;
    /**
     * `to_local + to_remote`: fiber only reads the sum.
     */
    liquidCapacityShannons: bigint;
    /**
     * TLC-adjusted, before the reserved CKB each side adds on non-UDT channels.
     */
    settlementLocalShannons: bigint;
    settlementRemoteShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
    tlcs: SettlementTlc[];
    commitmentLock: ScriptTemplate;
    /**
     * Shapes the lock args, each TLC record of the witness and the fee mock.
     */
    lockLayout: CommitmentLockLayout;
};

export type ShutdownTxInput = {
    fundingOutPoint: OutPoint;
    remoteFundingPubkey: Uint8Array;
    localCloseScript: Script;
    remoteCloseScript: Script;
    /**
     * Each side pays its own fee at its own rate, over the same mock size.
     */
    localFeeRate: bigint;
    remoteFeeRate: bigint;
    cellDepsCount: number;
    udtTypeScript: Script | null;
    toLocalShannons: bigint;
    toRemoteShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
};

/**
 * The tx carries neither fee rate, so the device rebuilds it from the outputs it judges. CKB channels only.
 */
export type ClosingTxInput = {
    fundingOutPoint: OutPoint;
    remoteFundingPubkey: Uint8Array;
    localCloseScript: Script;
    remoteCloseScript: Script;
    localCapacityShannons: bigint;
    remoteCapacityShannons: bigint;
};

/**
 * Not a transaction: a hash over one synthetic output plus the revoked commitment cell's lock args.
 */
export type RevocationInput = {
    /**
     * `false` on the sending side of a `revoke_and_ack`, `true` on the receiving side.
     */
    forRemote: boolean;
    /**
     * The revoked side's current commitment number minus one, as fiber computes it.
     */
    revokedCommitmentNumber: number;
    /**
     * The counterparty's close script when sending, the device's own when receiving.
     */
    payoutScript: Script;
    remoteFundingPubkey: Uint8Array;
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    cellDepsCount: number;
    udtTypeScript: Script | null;
    /**
     * `to_local + to_remote`: fiber only reads the sum.
     */
    liquidCapacityShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
    /**
     * The commitment fee is sized over a mock carrying this lock, so the digest depends on it.
     */
    commitmentLock: ScriptTemplate;
    /**
     * The revoked args carry no feature byte, but the commitment mock the fee is sized over does.
     */
    lockLayout: CommitmentLockLayout;
};

export type ChannelAnnouncementInput = {
    chainHash: Uint8Array;
    fundingOutPoint: OutPoint;
    /**
     * In either order: the announcement sorts them.
     */
    nodeIds: [Uint8Array, Uint8Array];
    remoteFundingPubkey: Uint8Array;
    /**
     * The liquid capacity, `to_local + to_remote`.
     */
    capacityShannons: bigint;
    udtTypeScript: Script | null;
};

export type SigningSettlementTlc = {
    tlcId: number;
    /**
     * From fiber's `inbound`, which is relative to the device in both views.
     */
    direction: TlcDirection;
    hashAlgorithm: TlcHashAlgorithm;
    amountShannons: bigint;
    paymentHash: Uint8Array;
    expiryMs: bigint;
    localKeyCommitmentNumber: number;
    /**
     * The node's claim; refused unless the device derives the same key.
     */
    localKeyPubkey: Uint8Array;
    remoteTlcPubkey: Uint8Array;
};

/**
 * Fiber's snapshot behind a commitment request, trusted only once the commitment rebuilt from it hashes to the node's tx.
 */
export type SigningSettlement = {
    /**
     * TLC-adjusted, each side's reserve already added.
     */
    localAmountShannons: bigint;
    remoteAmountShannons: bigint;
    localSettlementPubkey: Uint8Array;
    remoteSettlementPubkey: Uint8Array;
    forRemote: boolean;
    tlcs: SigningSettlementTlc[];
};

export type CommitmentSettlementTerms = {
    fundingOutPoint: OutPoint;
    remoteFundingPubkey: Uint8Array;
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    cellDepsCount: number;
    udtTypeScript: Script | null;
    liquidCapacityShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
    commitmentLock: ScriptTemplate;
    lockLayout: CommitmentLockLayout;
};
