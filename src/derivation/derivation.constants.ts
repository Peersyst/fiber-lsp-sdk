export const SECRET_KEY_LENGTH = 32;
export const CHANNEL_SEED_LENGTH = 32;
export const MASTER_SEED_LENGTH = 32;

/**
 * BIP39 expands any mnemonic into exactly this: a shorter input is a miswired host, not a shorter seed.
 */
export const BIP39_SEED_LENGTH = 64;

/**
 * BIP43 purpose: lnd's, outside the purposes a wallet spends from.
 */
export const MASTER_SEED_PURPOSE = 1017;

/**
 * SLIP-44 coin type of CKB.
 */
export const MASTER_SEED_COIN_TYPE = 309;

/**
 * The account level is hardened: 31 bits.
 */
export const MAX_ACCOUNT_INDEX = 2 ** 31 - 1;

/**
 * Additive only: changing a derivation strands existing channels, so it takes a new version.
 */
export const DERIVATION_SCHEME_VERSION = 1;

/**
 * The commitment secret chain reads only the low 48 bits; above this a secret and its nonce repeat.
 */
export const MAX_COMMITMENT_NUMBER = 2 ** 48 - 1;

/**
 * The index is formatted into the seed string: beyond this two indices collide.
 */
export const MAX_CHANNEL_INDEX = Number.MAX_SAFE_INTEGER;

/**
 * Beyond this, two indices format to the same preimage string.
 */
export const MAX_INVOICE_INDEX = MAX_CHANNEL_INDEX;

/**
 * A cooperative close signs in the `COMMITMENT` slot of its number: fiber's nonce purposes have no close of their own.
 */
export const NONCE_CONTEXTS = ["COMMITMENT", "REVOKE", "ANNOUNCEMENT"] as const;
