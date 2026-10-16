import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { truncatePaymentHash } from "../../common";
import type { PolicyViewTlc } from "../policy.types";

/**
 * Cuts a payment hash to its bound part, the key payment records are filed under.
 * @param paymentHashHex The full payment hash, lowercase hex.
 * @returns Its first 20 bytes, lowercase hex.
 */
export function boundPaymentHashOf(paymentHashHex: string): string {
    return bytesToHex(truncatePaymentHash(hexToBytes(paymentHashHex)));
}

/**
 * Tells whether a TLC found under a payment record's key is the record's: by the whole hash when it binds one, else by the key.
 * @param tlc The TLC, listed under the record's bound payment hash.
 * @param record The payment record filed under that hash.
 * @returns Whether the TLC is the record's.
 */
export function isTlcOfPaymentRecord(tlc: Pick<PolicyViewTlc, "fullPaymentHash">, record: { paymentHash: string }): boolean {
    return tlc.fullPaymentHash === null || tlc.fullPaymentHash === record.paymentHash;
}
