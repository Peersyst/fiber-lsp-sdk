import type { Invoice, InvoiceCurrency } from "../../invoice";
import { decodeInvoice, findInvoiceAttribute } from "../../invoice";
import { SDK_INVOICE_UNPAYABLE } from "../sdk.constants";
import { SdkError } from "../sdk.error";
import type { SdkPayableInvoice } from "../sdk.types";
import { describeSdkFailure } from "./failure.utils";
import { computeSdkInvoiceExpiryMs } from "./invoice-expiry.utils";

/**
 * Checks that an invoice is one the device pays: signed, in the network's currency, of a CKB amount, to a payee, not expired.
 * @param encodedInvoice The invoice string.
 * @param currency The network's invoice currency.
 * @param nowMs The host's clock.
 * @returns The payment hash, the amount and the payee's key.
 */
export function checkPayableInvoice(encodedInvoice: string, currency: InvoiceCurrency, nowMs: number): SdkPayableInvoice {
    const invoice = decodePayableInvoice(encodedInvoice);
    if (invoice.currency !== currency) refuseInvoice("currency", `is ${invoice.currency}, not the network's ${currency}`);
    const { amountShannons } = invoice;
    if (amountShannons === null) refuseInvoice("amountShannons", "is missing");
    if (amountShannons === "0") refuseInvoice("amountShannons", "is 0");
    if (findInvoiceAttribute(invoice, "udtScript") !== undefined) refuseInvoice("udtScript", "is present: only CKB is paid");
    const payee = findInvoiceAttribute(invoice, "payeePublicKey");
    if (payee === undefined) refuseInvoice("payeePublicKey", "is missing");
    const expiresAtMs = computeSdkInvoiceExpiryMs(invoice);
    // A millisecond stricter than fiber's `<` (`fiber-types/src/invoice.rs:865-878`), whose check runs after the device's.
    if (expiresAtMs !== null && expiresAtMs <= BigInt(nowMs)) {
        refuseInvoice("expiryTime", `ran out at ${expiresAtMs}, the device's clock reading ${nowMs}`);
    }
    return { paymentHash: invoice.paymentHash, amountShannons, payeePublicKey: payee.publicKey };
}

/**
 * Decodes the invoice string; the decoder refuses an unsigned one and any fiber's encoder would not write.
 * @param encodedInvoice The invoice string.
 * @returns The invoice.
 */
function decodePayableInvoice(encodedInvoice: string): Invoice {
    try {
        return decodeInvoice(encodedInvoice);
    } catch (error) {
        throw new SdkError("invoice_unpayable", describeSdkFailure(`${SDK_INVOICE_UNPAYABLE}: encodedInvoice does not decode`, error), {
            cause: error,
        });
    }
}

/**
 * Refuses the invoice, naming what makes it unpayable.
 * @param field The invoice's field or attribute type that failed.
 * @param detail What is wrong with it.
 */
function refuseInvoice(field: string, detail: string): never {
    throw new SdkError("invoice_unpayable", `${SDK_INVOICE_UNPAYABLE}: ${field} ${detail}`);
}
