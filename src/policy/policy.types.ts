import type { NonceContext } from "../derivation";
import type { CHANNEL_POLICY_RECORD_VERSION } from "./policy.constants";

/**
 * One sign-once slot: at most one distinct message is ever signed per (channel, commitment number, context).
 */
export type SignSlot = `${NonceContext}:${number}`;

/**
 * Per-channel state the device persists; the node remains the durable store for channel state.
 */
export type ChannelPolicyRecord = {
    version: typeof CHANNEL_POLICY_RECORD_VERSION;
    /**
     * The one piece recovery cannot re-seed from the node.
     */
    channelIndex: number;
    /**
     * Strictly increasing per context.
     */
    lastSignedCommitmentNumbers: Partial<Record<NonceContext, number>>;
    /**
     * Sign-once registry: kept so a re-delivered request is answered identically and a different message is refused.
     */
    signedDigests: Partial<Record<SignSlot, string>>;
    /**
     * Non-decreasing.
     */
    lastStateVersion: number;
    /**
     * Local balance after the last signed commitment, in decimal shannons.
     */
    localBalanceShannons: string;
    /**
     * User-initiated debits not yet consumed by a balance-decreasing commitment, in decimal shannons.
     */
    pendingDebitsShannons: string[];
};
