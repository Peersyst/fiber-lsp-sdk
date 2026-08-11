// Fiber amounts are u128 shannons.
export const MAX_AMOUNT_SHANNONS = (1n << 128n) - 1n;

/**
 * secp256k1 compressed encoding, which every point crossing the wire uses: public keys and commitment points alike.
 */
export const COMPRESSED_POINT_LENGTH = 33;

/**
 * What fiber's `compute_tx_message` produces, and therefore the only thing the device ever signs.
 */
export const MESSAGE_DIGEST_LENGTH = 32;

/**
 * Payments are hash-locked on sha256: the preimage is 32 bytes and so is its hash.
 */
export const PAYMENT_HASH_LENGTH = 32;

export const PREIMAGE_LENGTH = 32;
