import { NONCE_CONTEXTS } from "../../derivation";
import { CHANNEL_POLICY_RECORD_VERSION, CHANNEL_WATERMARK_VERSION } from "../policy.constants";
import type { ChannelPolicyRecord, ChannelWatermark, SignSlot } from "../policy.types";
import { signSlotKey } from "./slot.utils";

/**
 * Projects a record onto what a reinstall has to find again: the counters, the top slot of each context, and the exposure.
 * @param record Record being written.
 * @returns The watermark the recovery storage holds for that channel.
 */
export function projectChannelWatermark(record: ChannelPolicyRecord): ChannelWatermark {
    const signedSessions: Partial<Record<SignSlot, string>> = {};
    for (const context of NONCE_CONTEXTS) {
        const commitmentNumber = record.lastSignedCommitmentNumbers[context];
        if (commitmentNumber === undefined) continue;
        const slotKey = signSlotKey({ context, commitmentNumber });
        const commitment = record.signedSessions[slotKey];
        if (commitment !== undefined) signedSessions[slotKey] = commitment;
    }
    return {
        version: CHANNEL_WATERMARK_VERSION,
        lastSignedCommitmentNumbers: { ...record.lastSignedCommitmentNumbers },
        signedSessions,
        lastStateVersion: record.lastStateVersion,
        localExposureShannons: record.localExposureShannons,
    };
}

/**
 * Builds the record a channel starts from, which is the watermark expanded whenever the index has one.
 * @param channelId Channel identifier the record takes as its name.
 * @param watermark Watermark found at the index, or `null` when the index has never signed under this device.
 * @param localExposureShannons Exposure to start from, used only when there is no watermark to take it from.
 * @returns The record to persist.
 */
export function buildChannelRecord(
    channelId: string,
    watermark: ChannelWatermark | null,
    localExposureShannons: string,
): ChannelPolicyRecord {
    return {
        version: CHANNEL_POLICY_RECORD_VERSION,
        channelId,
        lastSignedCommitmentNumbers: watermark?.lastSignedCommitmentNumbers ?? {},
        signedSessions: watermark?.signedSessions ?? {},
        lastStateVersion: watermark?.lastStateVersion ?? 0,
        // The device's own number wins: the node's is the only one an attacker writes.
        localExposureShannons: watermark?.localExposureShannons ?? localExposureShannons,
        pendingDebitsShannons: [],
    };
}
