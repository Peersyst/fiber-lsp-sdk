import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { truncatePaymentHash } from "../../common";

/**
 * Cuts a payment hash to its bound part, the key payment records are filed under.
 * @param paymentHashHex The full payment hash, lowercase hex.
 * @returns Its first 20 bytes, lowercase hex.
 */
export function boundPaymentHashOf(paymentHashHex: string): string {
    return bytesToHex(truncatePaymentHash(hexToBytes(paymentHashHex)));
}
