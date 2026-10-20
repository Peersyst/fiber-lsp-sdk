import type { NonceCounter } from "../../src/policy";
import type { RevocationCaseVector } from "./interop-vectors";

// Fiber signs a close with the commitment nonce at the local number, which the shutdown vectors do not carry.
export const SHUTDOWN_NONCE_NUMBER = 20;

// Fiber's off-by-one: a revocation signs with the nonce one above the number it revokes.
export function revocationNonceNumber(kase: RevocationCaseVector): number {
    return kase.revoked_commitment_number + 1;
}

// The counter the revoked commitment's version counts, which fiber reads the slot from.
export function revocationCounter(kase: RevocationCaseVector): NonceCounter {
    return kase.for_remote ? "local" : "remote";
}
