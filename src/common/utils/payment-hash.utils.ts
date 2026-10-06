import { TRUNCATED_PAYMENT_HASH_LENGTH } from "../common.constants";

/**
 * Cuts a payment hash to what a TLC's settlement witness entry binds of it.
 * @param paymentHash The full payment hash.
 * @returns Its first 20 bytes.
 */
export function truncatePaymentHash(paymentHash: Uint8Array): Uint8Array {
    return paymentHash.slice(0, TRUNCATED_PAYMENT_HASH_LENGTH);
}
