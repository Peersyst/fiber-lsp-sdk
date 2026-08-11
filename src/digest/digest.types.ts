/**
 * The four values of the molecule `hash_type` byte, encoded as `data 0, type 1, data1 2, data2 4`.
 */
export type ScriptHashType = "data" | "type" | "data1" | "data2";

export type Script = {
    codeHash: Uint8Array;
    hashType: ScriptHashType;
    args: Uint8Array;
};

/**
 * A script minus its args: what the device pins per network for locks whose args it computes itself.
 */
export type ScriptTemplate = {
    codeHash: Uint8Array;
    hashType: ScriptHashType;
};

export type OutPoint = {
    txHash: Uint8Array;
    index: number;
};

export type TlcDirection = "offered" | "received";

/**
 * The two hash locks fiber's TLCs support, encoded in the witness flag byte as `ckb-hash 0, sha256 1`.
 */
export type TlcHashAlgorithm = "ckb-hash" | "sha256";

/**
 * One TLC of the settlement witness, as the node attaches it: selection and status filtering happen node-side, the
 * device only binds the signature to the set it was shown.
 */
export type SettlementTlc = {
    /**
     * Fiber's numeric TLC id, the witness sort key.
     */
    id: number;
    /**
     * Direction from the device's side of the channel, before any `forRemote` flip.
     */
    direction: TlcDirection;
    hashAlgorithm: TlcHashAlgorithm;
    amountShannons: bigint;
    paymentHash: Uint8Array;
    /**
     * Absolute expiry in milliseconds; the witness truncates it to whole seconds.
     */
    expiryMs: bigint;
    /**
     * The remote commitment number at the TLC's creation, the index of the device's per-TLC key.
     */
    createdAtRemoteCommitmentNumber: number;
    /**
     * The peer's commitment point at the TLC's creation (its local number); peer state the device cannot derive.
     */
    remoteCommitmentPoint: Uint8Array;
};

/**
 * Everything a commitment tx digest is a function of, besides the channel keys.
 */
export type CommitmentTxInput = {
    /**
     * Fiber's direction parameter: `true` builds the tx the device signs into its outgoing `commitment_signed`.
     */
    forRemote: boolean;
    fundingOutPoint: OutPoint;
    remoteFundingPubkey: Uint8Array;
    remoteTlcBasePubkey: Uint8Array;
    /**
     * The version in the lock args: the local commitment number when `forRemote`, the remote one otherwise.
     */
    commitmentNumber: number;
    /**
     * The negotiated `EpochNumberWithFraction` full value of the commitment delay.
     */
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    /**
     * Cell deps of the funding lock plus the UDT's, mocked into fee sizing even though the digest blanks them.
     */
    cellDepsCount: number;
    udtTypeScript: Script | null;
    /**
     * Raw channel balances; they size the output capacity (and the UDT liquid data), not the settlement witness.
     */
    toLocalShannons: bigint;
    toRemoteShannons: bigint;
    /**
     * TLC-adjusted balances of the settlement witness, before the reserved CKB each side adds on non-UDT channels.
     */
    settlementLocalShannons: bigint;
    settlementRemoteShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
    tlcs: SettlementTlc[];
    commitmentLock: ScriptTemplate;
};

/**
 * Everything a cooperative-close (shutdown) tx digest is a function of, besides the channel keys.
 */
export type ShutdownTxInput = {
    fundingOutPoint: OutPoint;
    remoteFundingPubkey: Uint8Array;
    localCloseScript: Script;
    remoteCloseScript: Script;
    /**
     * Each side pays its own fee from its own advertised rate, over the same mock size.
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
 * Everything a revocation digest is a function of, besides the channel keys. Not a transaction: the message is a hash
 * over one synthetic output plus the revoked commitment cell's lock args.
 */
export type RevocationInput = {
    /**
     * Fiber's direction parameter: `false` on the sending side of a `revoke_and_ack`, `true` on the receiving side.
     */
    forRemote: boolean;
    /**
     * The number in the signed args: the current commitment number of the revoked side minus one, as fiber computes it.
     */
    revokedCommitmentNumber: number;
    /**
     * The close script the swept funds go to: the counterparty's when sending, the device's own when receiving.
     */
    payoutScript: Script;
    remoteFundingPubkey: Uint8Array;
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    cellDepsCount: number;
    udtTypeScript: Script | null;
    toLocalShannons: bigint;
    toRemoteShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
    /**
     * The commitment fee is sized over a mock carrying this lock, so the revocation digest depends on it too.
     */
    commitmentLock: ScriptTemplate;
};

/**
 * Everything a channel announcement digest is a function of, besides the channel keys.
 */
export type ChannelAnnouncementInput = {
    chainHash: Uint8Array;
    fundingOutPoint: OutPoint;
    /**
     * The two node identity pubkeys, in either order: the announcement sorts them lexicographically.
     */
    nodeIds: [Uint8Array, Uint8Array];
    remoteFundingPubkey: Uint8Array;
    /**
     * The channel's liquid capacity, `to_local + to_remote`.
     */
    capacityShannons: bigint;
    udtTypeScript: Script | null;
};
