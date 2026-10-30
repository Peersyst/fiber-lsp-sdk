import { bytesToHex } from "@noble/hashes/utils.js";
import type { SdkChannelEvidence } from "@peersyst/fiber-lsp-sdk";
import { bareLowerHex } from "./agent.utils";

export type AgentStatusChannel = {
    channelId: string;
    evidence: Pick<SdkChannelEvidence, "revocations" | "watchtowerSignatures">;
};

export type AgentStatusInput = {
    tenantId: string;
    rootSignerPubkey: Uint8Array | string;
    tenantToken: string | null;
    channels: AgentStatusChannel[];
};

export type WatchtowerSubmissionJson = {
    request_id: string;
    key_purpose: { type: "Settlement" } | { type: "Tlc"; commitment_number: string };
};

/**
 * Fiber's `CommitmentReference` without its `tx_hash`: the SDK's evidence does not keep the revoked commitment's hash.
 */
export type RevokedCommitmentJson = {
    for_remote: boolean;
    version: number;
};

/**
 * The status file of fiber's test agent, keys in its order.
 */
export type AgentStatusJson = {
    tenant_id: string;
    root_signer_pubkey: string;
    tenant_token: string | null;
    /**
     * A marker: the SDK allocates the open's signer at open, so there is no material to publish before.
     */
    channel_open_signer_material: { allocated_at_open: true } | null;
    bound_channel_ids: string[];
    watchtower_submissions: Record<string, WatchtowerSubmissionJson[]>;
    revoked_commitments: Record<string, RevokedCommitmentJson[]>;
};

/**
 * Writes hex without `0x`, lowercase, refusing what is not hex bytes.
 * @param hex The hex, with or without `0x`.
 * @returns The bare lowercase hex.
 */
function bareHex(hex: string): string {
    const bare = bareLowerHex(hex);
    if (!/^([0-9a-f]{2})+$/.test(bare)) throw new Error(`${hex} is not hex bytes`);
    return bare;
}

/**
 * Writes the agent's state as fiber's status JSON.
 * @param input The tenant, the root signer, the token and the bound channels with their evidence.
 * @returns The status, as fiber's agent writes it.
 */
export function agentStatus(input: AgentStatusInput): AgentStatusJson {
    const channels = new Map<string, AgentStatusChannel["evidence"]>();
    for (const { channelId, evidence } of input.channels) {
        const id = `0x${bareHex(channelId)}`;
        if (channels.has(id)) throw new Error(`channel ${id} is bound twice`);
        channels.set(id, evidence);
    }
    const bound = [...channels].sort(([a], [b]) => (a < b ? -1 : 1));
    const watchtowerSubmissions: Record<string, WatchtowerSubmissionJson[]> = {};
    const revokedCommitments: Record<string, RevokedCommitmentJson[]> = {};
    for (const [id, evidence] of bound) {
        const submissions = evidence.watchtowerSignatures
            .filter(({ applied }) => applied)
            .map(({ requestId, purpose }): WatchtowerSubmissionJson => ({
                request_id: requestId,
                key_purpose:
                    purpose.kind === "settlement"
                        ? { type: "Settlement" }
                        : { type: "Tlc", commitment_number: `0x${purpose.commitmentNumber.toString(16)}` },
            }));
        // As fiber's agent, which keys a channel in its receipts at its first submission.
        if (submissions.length > 0) watchtowerSubmissions[id] = submissions;
        revokedCommitments[id] = evidence.revocations.map(({ forRemote, version }) => ({ for_remote: forRemote, version }));
    }
    return {
        tenant_id: bareHex(input.tenantId),
        root_signer_pubkey:
            typeof input.rootSignerPubkey === "string" ? bareHex(input.rootSignerPubkey) : bytesToHex(input.rootSignerPubkey),
        tenant_token: input.tenantToken,
        channel_open_signer_material: bound.length === 0 ? { allocated_at_open: true } : null,
        bound_channel_ids: bound.map(([id]) => id),
        watchtower_submissions: watchtowerSubmissions,
        revoked_commitments: revokedCommitments,
    };
}
