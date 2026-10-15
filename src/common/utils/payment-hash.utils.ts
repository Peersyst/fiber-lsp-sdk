import { TRUNCATED_PAYMENT_HASH_LENGTH } from "../common.constants";

/**
 * Cuts a payment hash to what a legacy settlement witness binds of it, the key the payment records are filed under.
 * @param paymentHash The full payment hash.
 * @returns Its first 20 bytes.
 */
export function truncatePaymentHash(paymentHash: Uint8Array): Uint8Array {
    return paymentHash.slice(0, TRUNCATED_PAYMENT_HASH_LENGTH);
}
