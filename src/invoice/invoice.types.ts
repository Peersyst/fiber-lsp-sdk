import type { Script, TlcHashAlgorithm } from "../common";
import type { INVOICE_ATTRIBUTE_TYPES, INVOICE_CURRENCIES } from "./invoice.constants";

export type InvoiceCurrency = (typeof INVOICE_CURRENCIES)[number];

export type InvoiceAttributeType = (typeof INVOICE_ATTRIBUTE_TYPES)[number];

// Keyed by every attribute type, so one added to `INVOICE_ATTRIBUTE_TYPES` alone fails to compile.
type InvoiceAttributeValues = {
    expiryTime: { seconds: bigint };
    description: { text: string };
    /**
     * Deprecated: fiber's builder refuses it, its codec still carries it.
     */
    finalHtlcTimeout: { milliseconds: bigint };
    finalHtlcMinimumExpiryDelta: { milliseconds: bigint };
    fallbackAddr: { address: string };
    /**
     * Fiber's feature bit vector, as raw bytes.
     */
    feature: { bits: Uint8Array };
    udtScript: { script: Script };
    /**
     * Compressed, 33 bytes; an uncompressed key is refused, since fiber writes it back compressed.
     */
    payeePublicKey: { publicKey: Uint8Array };
    hashAlgorithm: { algorithm: TlcHashAlgorithm };
    paymentSecret: { secret: Uint8Array };
};

export type InvoiceAttribute = {
    [Type in InvoiceAttributeType]: { type: Type } & InvoiceAttributeValues[Type];
}[InvoiceAttributeType];

export type UnsignedInvoice = {
    currency: InvoiceCurrency;
    /**
     * `null` lets the payer choose.
     */
    amountShannons: string | null;
    timestampMs: bigint;
    paymentHash: Uint8Array;
    /**
     * In string order, which the signature covers.
     */
    attributes: InvoiceAttribute[];
};

export type Invoice = UnsignedInvoice & {
    /**
     * `r || s || recovery id`.
     */
    signature: Uint8Array;
};
