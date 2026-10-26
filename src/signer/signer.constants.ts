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

/**
 * Fiber's `TENANT_REGISTRY_PROTOCOL` (`fiber-types/src/hosted_lsp.rs:11`), the prefix of the registration payload.
 */
export const TENANT_REGISTRY_PROTOCOL = "fiber-hosted-lsp-tenant-registry/v1";

/**
 * Fiber's `TENANT_ID_DOMAIN` (`fiber-types/src/hosted_lsp.rs:14`), the salt of the tenant id's hash.
 */
export const TENANT_ID_DOMAIN = "fiber-hosted-lsp-tenant-id/v1";

/**
 * The epoch length enters `tlc_expiry_delay`'s f64 arithmetic, exact for integers up to here.
 */
export const MAX_MILLISECONDS_PER_EPOCH = Number.MAX_SAFE_INTEGER;
