export const SECRET_KEY_LENGTH = 32;
export const DIGEST_LENGTH = 32;
export const CHANNEL_SEED_LENGTH = 32;
export const MASTER_SEED_LENGTH = 32;

/**
 * BIP39 expands any mnemonic into exactly this: a shorter input is a miswired host, not a shorter seed.
 */
export const BIP39_SEED_LENGTH = 64;

/**
 * BIP43 purpose of the master seed path: 1017 is lnd's, and it is outside the purposes a wallet spends from.
 */
export const MASTER_SEED_PURPOSE = 1017;

/**
 * SLIP-44 coin type of CKB.
 */
export const MASTER_SEED_COIN_TYPE = 309;

/**
 * The account level of the path is hardened, and a hardened index is 31 bits.
 */
export const MAX_ACCOUNT_INDEX = 2 ** 31 - 1;

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
