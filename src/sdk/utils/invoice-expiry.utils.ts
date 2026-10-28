import { MILLISECONDS_PER_SECOND } from "../../common";
import type { Invoice } from "../../invoice";
import { findInvoiceAttribute } from "../../invoice";

/**
 * Computes when an invoice expires as fiber's `is_expired` counts it (`fiber-types/src/invoice.rs:865-878`): timestamp plus expiry.
 * @param invoice The decoded invoice.
 * @returns Milliseconds since the epoch, or `null` when the invoice never expires.
 */
export function computeSdkInvoiceExpiryMs(invoice: Invoice): bigint | null {
    const expiry = findInvoiceAttribute(invoice, "expiryTime");
    return expiry === undefined ? null : invoice.timestampMs + expiry.seconds * MILLISECONDS_PER_SECOND;
}
