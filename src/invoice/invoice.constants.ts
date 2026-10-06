import type { InvoiceCurrency } from "./invoice.types";

/**
 * Mainnet, testnet and any other chain.
 */
export const INVOICE_CURRENCIES = ["Fibb", "Fibt", "Fibd"] as const;

/**
 * The amount follows the prefix in plain decimal, with no multiplier.
 */
export const INVOICE_CURRENCY_PREFIXES = { Fibb: "fibb", Fibt: "fibt", Fibd: "fibd" } as const satisfies Record<InvoiceCurrency, string>;

/**
 * Fiber's `InvoiceAttr` union in schema order: the index is the item id.
 */
export const INVOICE_ATTRIBUTE_TYPES = [
    "expiryTime",
    "description",
    "finalHtlcTimeout",
    "finalHtlcMinimumExpiryDelta",
    "fallbackAddr",
    "feature",
    "udtScript",
    "payeePublicKey",
    "hashAlgorithm",
    "paymentSecret",
] as const;

export const INVOICE_SIGNATURE_LENGTH = 65;

export const INVOICE_SIGNATURE_GROUPS = 104;

/**
 * Fiber's decoder limit, which bounds what a short compressed stream can expand to.
 */
export const MAX_INVOICE_DATA_LENGTH = 16384;
