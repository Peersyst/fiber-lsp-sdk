import type { TlcHashAlgorithmWire } from "../../src/wire";

export function wireHex(hex: string): string {
    return `0x${hex}`;
}

// Not read from `src`, so a map that swaps the names cannot round-trip green.
export const HASH_ALGORITHM_WIRE: Record<string, TlcHashAlgorithmWire> = { "ckb-hash": "ckb_hash", sha256: "sha256" };
