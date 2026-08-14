import type { NonceContext } from "../derivation";
import type { ChannelAnnouncementInput, CommitmentTxInput, RevocationInput, ShutdownTxInput } from "../digest";
import type { CHANNEL_POLICY_RECORD_VERSION } from "./policy.constants";

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
    /**
     * Fiber's TLC-adjusted settlement amount, not the raw balance, in decimal shannons.
     */
    localExposureShannons: string;
    pendingDebitsShannons: string[];
};

export type SignSession = {
    orderedPublicKeys: Uint8Array[];
    aggregatedNonce: Uint8Array;
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
     * The number the nonce slot is keyed by, which is not always the number inside the message.
     */
    nonceCommitmentNumber: number;
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
