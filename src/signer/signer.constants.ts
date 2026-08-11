/**
 * A BIP-327 public nonce is two compressed points, and an aggregated nonce shares the encoding.
 */
export const PUBLIC_NONCE_LENGTH = 66;

export const PARTIAL_SIGNATURE_LENGTH = 32;

/**
 * Fiber funding locks are strictly 2-of-2: a longer list is a different protocol, not a bigger channel.
 */
export const MUSIG_PARTICIPANTS = 2;
