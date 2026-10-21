import type { ChannelSigningTransition } from "../protocol";

/**
 * Funding-cell spends sort the keys (`fiber-lib/src/fiber/channel.rs:11029-11042`); a revocation keeps the role order of the
 * lock it revokes (`:11120-11129`). Any other order aggregates a key nothing is locked under.
 */
export const SIGNING_KEY_ORDERS = {
    SendCommitmentSigned: "ascending",
    CompleteReceivedCommitment: "ascending",
    SendRevokeAndAck: "peer-first",
    CompleteReceivedRevokeAndAck: "device-first",
    SendClosingSigned: "ascending",
    SignChannelAnnouncement: "ascending",
} as const satisfies Record<ChannelSigningTransition, "ascending" | "peer-first" | "device-first">;
