// Namespaced: the host may back the storage with a store it also uses for its own keys.
export const STORAGE_KEY_NAMESPACE = "fiber-lsp-sdk";

export const CHANNEL_RECORD_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:channel:`;
export const HOLD_INVOICE_PREIMAGE_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:preimage:`;

/**
 * Bumped on format changes so old records migrate instead of being rejected: a rejected record loses its sign-once registry.
 */
export const CHANNEL_POLICY_RECORD_VERSION = 1;
