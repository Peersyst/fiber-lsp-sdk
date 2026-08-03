export const SECRET_KEY_LENGTH = 32;
export const COMPRESSED_POINT_LENGTH = 33;
export const DIGEST_LENGTH = 32;
export const CHANNEL_SEED_LENGTH = 32;
export const MASTER_SEED_LENGTH = 32;

/**
 * Additive only: changing a derivation strands existing channels, so it takes a new version.
 */
export const DERIVATION_SCHEME_VERSION = 1;

/**
 * The commitment secret chain reads only the low 48 bits; above this it reuses a secret and its musig2 nonce.
 */
export const MAX_COMMITMENT_NUMBER = 2 ** 48 - 1;

/**
 * The index is formatted into the seed string, so beyond this two indices collide onto one seed.
 */
export const MAX_CHANNEL_INDEX = Number.MAX_SAFE_INTEGER;

export const NONCE_CONTEXTS = ["COMMITMENT", "REVOKE", "CLOSE", "ANNOUNCEMENT"] as const;
