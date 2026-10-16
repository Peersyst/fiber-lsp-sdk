export const UINT32_MAX = 2 ** 32 - 1;
export const UINT64_MAX = (1n << 64n) - 1n;
export const UINT128_MAX = (1n << 128n) - 1n;

export const UINT32_LENGTH = 4;

export const UINT64_LENGTH = 8;

export const UINT128_LENGTH = 16;

/**
 * Fiber amounts are u128 shannons.
 */
export const MAX_AMOUNT_SHANNONS = UINT128_MAX;

export const SHANNONS_PER_CKB = 100_000_000n;

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
 * The prefix of a payment hash a TLC's settlement witness binds.
 */
export const TRUNCATED_PAYMENT_HASH_LENGTH = 20;

export const MILLISECONDS_PER_SECOND = 1000n;

/**
 * Past a signed 32-bit delay, `setTimeout` fires immediately.
 */
export const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

export const SCRIPT_HASH_TYPES = ["data", "type", "data1", "data2"] as const;

/**
 * The molecule `hash_type` byte: `DataN` encodes as `N << 1`, `type` as 1.
 */
export const SCRIPT_HASH_TYPE_BYTES = { data: 0, type: 1, data1: 2, data2: 4 } as const satisfies Record<
    (typeof SCRIPT_HASH_TYPES)[number],
    number
>;

export const DEP_TYPES = ["code", "dep_group"] as const;

export const TLC_DIRECTIONS = ["offered", "received"] as const;

/**
 * The two hash locks fiber's TLCs support.
 */
export const TLC_HASH_ALGORITHMS = ["ckb-hash", "sha256"] as const;

/**
 * Fiber's `HashAlgorithm` byte, the same in a TLC's witness flag and in an invoice's attribute.
 */
export const TLC_HASH_ALGORITHM_BYTES = { "ckb-hash": 0, sha256: 1 } as const satisfies Record<
    (typeof TLC_HASH_ALGORITHMS)[number],
    number
>;

export const SIGNER_ERROR_CODES = ["unknown_channel", "malformed", "stale_state", "policy_refusal"] as const;
