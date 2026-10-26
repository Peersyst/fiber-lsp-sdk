import { HASH256_LENGTH } from "../common";
import { missingPolicyRecord, unregisteredPolicyChannelMessage } from "../policy";
import type { ChannelPolicyRecord, SignedCommitmentRecord, SignerStore } from "../policy";
import { WIRE_HEX_PREFIX, assertWireHexBytes } from "../wire";
import { SdkError } from "./sdk.error";
import type { SdkChannelEvidence } from "./sdk.types";

/**
 * Reads the evidence a channel's record keeps.
 * @param store The device's store.
 * @param channelId The channel, under any name the node gave it.
 * @returns A copy of the evidence.
 */
export async function readSdkChannelEvidence(store: SignerStore, channelId: string): Promise<SdkChannelEvidence> {
    assertWireHexBytes("channelId", channelId, HASH256_LENGTH);
    const channelIndex = await store.resolveChannelIndex(channelId);
    if (channelIndex === null) throw new SdkError("unknown_channel", unregisteredPolicyChannelMessage(channelId));
    const record = await store.getChannelRecord(channelIndex);
    if (record === null) throw missingPolicyRecord(channelId, channelIndex);
    return projectChannelEvidence(record);
}

/**
 * Projects a channel's record onto its evidence.
 * @param record The record.
 * @returns The evidence.
 */
function projectChannelEvidence(record: ChannelPolicyRecord): SdkChannelEvidence {
    return {
        revocations: record.revocations.map(({ version, forRemote, signature }) => ({
            version,
            forRemote,
            signature: wireHexOf(signature),
        })),
        commitments: {
            local: commitmentEvidenceOf(record.commitmentHashes.local),
            remote: commitmentEvidenceOf(record.commitmentHashes.remote),
        },
        watchtowerSignatures: (record.watchtowerSpends ?? []).flatMap(({ requestId, purpose, signature, applied }) =>
            signature === null ? [] : [{ requestId: wireHexOf(requestId), purpose, signature: wireHexOf(signature), applied }],
        ),
    };
}

/**
 * Projects a view's last signed commitment onto its evidence.
 * @param commitment The view's record, absent until one is signed.
 * @returns The commitment's number and hash, or `null`.
 */
function commitmentEvidenceOf(commitment: SignedCommitmentRecord | undefined): SdkChannelEvidence["commitments"]["local"] {
    if (commitment === undefined) return null;
    return { commitmentNumber: commitment.commitmentNumber, txHash: wireHexOf(commitment.txHash) };
}

/**
 * Writes the record's lowercase hex as fiber's JSON does.
 * @param hex Lowercase hex without the prefix.
 * @returns The `0x`-prefixed hex.
 */
function wireHexOf(hex: string): string {
    return WIRE_HEX_PREFIX + hex;
}
