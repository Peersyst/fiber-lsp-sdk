import type { TlcHashAlgorithm } from "../common";

export const WIRE_HEX_PREFIX = "0x";

/**
 * Fiber's `HashAlgorithm` serializes in snake_case; the digest module keeps the hyphenated name.
 */
export const TLC_HASH_ALGORITHMS = { ckb_hash: "ckb-hash", sha256: "sha256" } as const satisfies Record<string, TlcHashAlgorithm>;
