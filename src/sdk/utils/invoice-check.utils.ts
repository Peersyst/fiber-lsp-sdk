import { equalBytes } from "@noble/curves/utils.js";
import type { Invoice, InvoiceAttribute, InvoiceAttributeType } from "../../invoice";
import { decodeInvoice, findInvoiceAttribute } from "../../invoice";
import { SDK_INVOICE_TIMESTAMP_SKEW_MS } from "../sdk.constants";
import { SdkError } from "../sdk.error";
import type { SdkInvoiceRequest } from "../sdk.types";
import { describeSdkFailure } from "./failure.utils";

type TenantInvoiceAttribute<Type extends InvoiceAttributeType> = Extract<InvoiceAttribute, { type: Type }>;

const REFUSED = "the node's invoice is refused:";

// What fiber's `new_invoice` writes for a tenant (`rpc/invoice.rs:184-197`, `290-399`); the description only when asked.
const TENANT_INVOICE_ATTRIBUTE_TYPES = [
    "description",
    "expiryTime",
    "feature",
    "trampolineRouteHint",
    "finalHtlcMinimumExpiryDelta",
    "hashAlgorithm",
    "payeePublicKey",
] as const satisfies readonly InvoiceAttributeType[];

// Trampoline routing's optional bit, which fiber's hint sets (`invoice/invoice_impl.rs:103-106`); any other changes what the payer does.
const TENANT_INVOICE_FEATURE_BITS = Uint8Array.of(0x20);

/**
 * Checks the node's `new_invoice` string against what the device asked.
 * @param invoiceAddress The node's string.
 * @param request What the device sent, and the LSP's key.
 * @param nowMs The host's clock, read once the node answered.
 */
export function checkTenantInvoice(invoiceAddress: string, request: SdkInvoiceRequest, nowMs: number): void {
    const invoice = decodeTenantInvoice(invoiceAddress);
    if (invoice.currency !== request.currency) rejectInvoice("currency", `is ${invoice.currency}, not the network's ${request.currency}`);
    if (invoice.amountShannons !== request.amountShannons) {
        rejectInvoice("amountShannons", `is ${invoice.amountShannons ?? "none"}, not the ${request.amountShannons} asked`);
    }
    // A past timestamp only shortens the invoice; a later one stretches fiber's expiry past the one asked.
    if (invoice.timestampMs > BigInt(nowMs) + SDK_INVOICE_TIMESTAMP_SKEW_MS) {
        rejectInvoice("timestampMs", `is ${invoice.timestampMs}, more than ${SDK_INVOICE_TIMESTAMP_SKEW_MS} ms past the device's ${nowMs}`);
    }
    if (!equalBytes(invoice.paymentHash, request.paymentHash)) rejectInvoice("paymentHash", "is not the hash the device derived");
    const { algorithm } = requireAttribute(invoice, "hashAlgorithm");
    if (algorithm !== request.hashAlgorithm) rejectInvoice("hashAlgorithm", `is ${algorithm}, not the ${request.hashAlgorithm} asked`);
    const { seconds } = requireAttribute(invoice, "expiryTime");
    if (seconds !== request.expirySeconds) rejectInvoice("expiryTime", `is ${seconds} s, not the ${request.expirySeconds} s asked`);
    const { milliseconds } = requireAttribute(invoice, "finalHtlcMinimumExpiryDelta");
    if (milliseconds !== request.finalExpiryDeltaMs) {
        rejectInvoice("finalHtlcMinimumExpiryDelta", `is ${milliseconds} ms, not the ${request.finalExpiryDeltaMs} ms asked`);
    }
    checkTenantInvoiceDescription(invoice, request.description);
    if (!equalBytes(requireAttribute(invoice, "feature").bits, TENANT_INVOICE_FEATURE_BITS)) {
        rejectInvoice("feature", "is not trampoline routing's optional bit alone");
    }
    if (!equalBytes(requireAttribute(invoice, "trampolineRouteHint").nodeId, request.lspPubkey)) {
        rejectInvoice("trampolineRouteHint", "is not the LSP's key");
    }
    // The decoder already held the signature to this key.
    requireAttribute(invoice, "payeePublicKey");
    const accepted: readonly InvoiceAttributeType[] = TENANT_INVOICE_ATTRIBUTE_TYPES;
    const extra = invoice.attributes.find((attribute) => !accepted.includes(attribute.type));
    if (extra !== undefined) rejectInvoice(extra.type, "was not asked for");
}

/**
 * Decodes the node's string; the decoder refuses any string fiber's encoder would not write.
 * @param invoiceAddress The node's string.
 * @returns The invoice.
 */
function decodeTenantInvoice(invoiceAddress: string): Invoice {
    try {
        return decodeInvoice(invoiceAddress);
    } catch (error) {
        throw new SdkError("invoice_rejected", describeSdkFailure(`${REFUSED} invoiceAddress does not decode`, error), { cause: error });
    }
}

/**
 * Checks that the invoice carries the description asked, or none when none was.
 * @param invoice The decoded invoice.
 * @param asked The description asked, if any.
 */
function checkTenantInvoiceDescription(invoice: Invoice, asked: string | undefined): void {
    const description = findInvoiceAttribute(invoice, "description");
    if (asked === undefined) {
        if (description !== undefined) rejectInvoice("description", "was not asked for");
        return;
    }
    if (requireAttribute(invoice, "description").text !== asked) rejectInvoice("description", "is not the one asked");
}

/**
 * Reads the invoice's attribute of a type, refusing an invoice that carries none.
 * @param invoice The decoded invoice.
 * @param type The attribute type.
 * @returns The attribute.
 */
function requireAttribute<Type extends InvoiceAttributeType>(invoice: Invoice, type: Type): TenantInvoiceAttribute<Type> {
    const attribute = findInvoiceAttribute(invoice, type);
    if (attribute === undefined) rejectInvoice(type, "is missing");
    return attribute;
}

/**
 * Refuses the node's invoice, naming what failed.
 * @param field The invoice's field or attribute type that failed.
 * @param detail What is wrong with it.
 */
function rejectInvoice(field: string, detail: string): never {
    throw new SdkError("invoice_rejected", `${REFUSED} ${field} ${detail}`);
}
