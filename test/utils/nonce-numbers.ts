import type { RevocationCaseVector } from "./interop-vectors";

/**
 * Fiber signs a close with the commitment nonce at the current local number, which the shutdown vectors do not carry.
 */
export const SHUTDOWN_NONCE_NUMBER = 20;

/**
 * Fiber's off-by-one: a revocation is signed with the nonce one above the number it revokes.
 * @param kase Revocation case of the vectors.
 * @returns The nonce number fiber signs it with.
 */
export function revocationNonceNumber(kase: RevocationCaseVector): number {
    return kase.revoked_commitment_number + 1;
}
