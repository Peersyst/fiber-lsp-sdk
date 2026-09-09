/**
 * Namespaced: the host may back the storage with a store it also uses for its own keys.
 */
export const STORAGE_KEY_NAMESPACE = "fiber-lsp-sdk";

/**
 * Keyed by channel index, the one name a channel never changes: everything a record protects derives from that index.
 */
export const CHANNEL_RECORD_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:channel:`;

/**
 * Channel id to channel index, many to one: fiber renames a channel when the open handshake fixes its id.
 */
export const CHANNEL_ALIAS_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:alias:`;
export const HOLD_INVOICE_PREIMAGE_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:preimage:`;

/**
 * Bumped on format changes so old records migrate instead of being rejected: a rejected record loses its sign-once registry.
 */
export const CHANNEL_POLICY_RECORD_VERSION = 1;

/**
 * The announcement nonce never rotates, so its slot is fixed and latched on first use.
 */
export const ANNOUNCEMENT_SLOT_NUMBER = 0;

/**
 * Stored format: changing it reopens every slot a device has already served.
 */
export const SESSION_COMMITMENT_LABEL = "fiber-lsp-sdk sign-once v1";

/**
 * Lives in the recovery storage, the one an uninstall does not reach.
 */
export const CHANNEL_WATERMARK_KEY_PREFIX = `${STORAGE_KEY_NAMESPACE}:watermark:`;

/**
 * Mirrored into both storages: an index handed out twice signs two channels under one nonce space.
 */
export const NEXT_CHANNEL_INDEX_KEY = `${STORAGE_KEY_NAMESPACE}:next-channel-index`;

/**
 * Versioned apart from the record: they live in different stores, so a record-only change must not rewrite a keychain.
 */
export const CHANNEL_WATERMARK_VERSION = 1;

/**
 * Indexes are handed out in sequence, so a gap is an index whose channel the node never came to know.
 */
export const CHANNEL_INDEX_SCAN_GAP = 20;

/**
 * Only reached when the counter is behind the storage.
 */
export const CHANNEL_INDEX_PROBE_LIMIT = 64;
