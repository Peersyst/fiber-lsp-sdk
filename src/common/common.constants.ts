export const UINT32_MAX = 2 ** 32 - 1;
export const UINT64_MAX = (1n << 64n) - 1n;
export const UINT128_MAX = (1n << 128n) - 1n;

/**
 * Fiber amounts are u128 shannons.
 */
export const MAX_AMOUNT_SHANNONS = UINT128_MAX;

export const HASH256_LENGTH = 32;

/**
 * secp256k1 compressed encoding, which every point crossing the wire uses: public keys and commitment points alike.
 */
export const COMPRESSED_POINT_LENGTH = 33;

/**
 * What fiber's `compute_tx_message` produces, and therefore the only thing the device ever signs.
 */
export const MESSAGE_DIGEST_LENGTH = 32;

/**
 * A BIP-327 public nonce is two compressed points, and an aggregated nonce shares the encoding.
 */
export const PUBLIC_NONCE_LENGTH = 66;

export const PARTIAL_SIGNATURE_LENGTH = 32;

export const X_ONLY_PUBLIC_KEY_LENGTH = 32;

export const SCHNORR_SIGNATURE_LENGTH = 64;

/**
 * Fiber funding locks are strictly 2-of-2: a longer list is a different protocol, not a bigger channel.
 */
export const MUSIG_PARTICIPANTS = 2;

/**
 * Payments are hash-locked on sha256: the preimage is 32 bytes and so is its hash.
 */
export const PAYMENT_HASH_LENGTH = 32;

export const PREIMAGE_LENGTH = 32;

/**
 * The four values of the molecule `hash_type` byte, encoded as `data 0, type 1, data1 2, data2 4`.
 */
export const SCRIPT_HASH_TYPES = ["data", "type", "data1", "data2"] as const;

export const TLC_DIRECTIONS = ["offered", "received"] as const;

export const SIGNER_ERROR_CODES = ["unknown_channel", "malformed", "stale_state", "policy_refusal"] as const;
