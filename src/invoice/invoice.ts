import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { assertBytes, assertDecimalShannons, assertOneOf, assertString, compareBytes, isDecimalShannons } from "../common";
import { arDecompress, arEncompress } from "./arithmetic-coder";
import { bytesToInvoiceGroups, decodeInvoiceBech32m, encodeInvoiceBech32m, invoiceGroupsToBytes } from "./bech32m";
import { decodeInvoiceData, encodeInvoiceData } from "./invoice-data";
import { INVOICE_CURRENCIES, INVOICE_CURRENCY_PREFIXES, INVOICE_SIGNATURE_GROUPS, INVOICE_SIGNATURE_LENGTH } from "./invoice.constants";
import { refuseInvoice } from "./invoice.error";
import type { Invoice, InvoiceAttribute, InvoiceCurrency, UnsignedInvoice } from "./invoice.types";
import { encodeInvoiceUtf8 } from "./utils";

type PayeeAttribute = Extract<InvoiceAttribute, { type: "payeePublicKey" }>;

const SIGNED_FLAG = 1;
const COMPACT_SIGNATURE_LENGTH = 64;
const MAX_RECOVERY_ID = 3;
// Fiber appends one zero byte to the signed stream unless its length is a multiple of this.
const DIGEST_BLOCK = 5;

/**
 * Writes the human-readable part: the currency's prefix, then the amount in plain decimal when there is one.
 * @param invoice The currency and the amount.
 * @returns The human-readable part.
 */
function hrpOf(invoice: Pick<UnsignedInvoice, "currency" | "amountShannons">): string {
    assertOneOf("currency", invoice.currency, INVOICE_CURRENCIES);
    if (invoice.amountShannons !== null) assertDecimalShannons("amountShannons", invoice.amountShannons);
    return `${INVOICE_CURRENCY_PREFIXES[invoice.currency]}${invoice.amountShannons ?? ""}`;
}

/**
 * Reads the human-readable part, refusing an amount fiber would write back otherwise.
 * @param hrp The human-readable part.
 * @returns The currency and the amount.
 */
function parseHrp(hrp: string): Pick<UnsignedInvoice, "currency" | "amountShannons"> {
    const currency = INVOICE_CURRENCIES.find((candidate: InvoiceCurrency) => hrp.startsWith(INVOICE_CURRENCY_PREFIXES[candidate]));
    if (currency === undefined) refuseInvoice("currency", `must be one of ${Object.values(INVOICE_CURRENCY_PREFIXES).join(", ")}`);
    const amount = hrp.slice(INVOICE_CURRENCY_PREFIXES[currency].length);
    if (amount !== "" && !isDecimalShannons(amount)) refuseInvoice("amount", "must be decimal shannons within u128, without leading zeros");
    return { currency, amountShannons: amount === "" ? null : amount };
}

/**
 * Port of fiber's `hash`: sha256 over the human-readable part and the padded compressed stream.
 * @param hrp The human-readable part.
 * @param compressed The compressed stream.
 * @returns The 32-byte digest.
 */
function signedDigest(hrp: string, compressed: Uint8Array): Uint8Array {
    const padding = compressed.length % DIGEST_BLOCK === 0 ? new Uint8Array(0) : new Uint8Array(1);
    return sha256(concatBytes(encodeInvoiceUtf8("hrp", hrp), compressed, padding));
}

/**
 * Computes the digest an invoice's payee signs, over fiber's own encoding of it.
 * @param invoice The invoice, without its signature.
 * @returns The 32-byte digest.
 */
export function computeInvoiceDigest(invoice: UnsignedInvoice): Uint8Array {
    return signedDigest(hrpOf(invoice), arEncompress(encodeInvoiceData(invoice)));
}

/**
 * Writes an invoice as the string fiber's encoder writes for it; the signature is written as given, not verified.
 * @param invoice The signed invoice.
 * @returns The bech32m string.
 */
export function encodeInvoice(invoice: Invoice): string {
    const hrp = hrpOf(invoice);
    const compressed = arEncompress(encodeInvoiceData(invoice));
    assertBytes("signature", invoice.signature, INVOICE_SIGNATURE_LENGTH);
    return encodeInvoiceBech32m(hrp, [SIGNED_FLAG, ...bytesToInvoiceGroups(compressed), ...bytesToInvoiceGroups(invoice.signature)]);
}

/**
 * Checks the signature is low-S, recoverable and, when the invoice carries a payee key, by that key.
 * @param signature The 65 signature bytes.
 * @param digest The digest it signs.
 * @param payeePublicKey The key of the payee attribute, or `undefined` without one.
 */
function verifySignature(signature: Uint8Array, digest: Uint8Array, payeePublicKey: Uint8Array | undefined): void {
    let compact: InstanceType<typeof secp256k1.Signature>;
    try {
        compact = secp256k1.Signature.fromBytes(signature.subarray(0, COMPACT_SIGNATURE_LENGTH), "compact");
    } catch {
        refuseInvoice("signature", "must have r and s within the curve order");
    }
    const recoveryId = signature[COMPACT_SIGNATURE_LENGTH] ?? 0;
    if (recoveryId > MAX_RECOVERY_ID) refuseInvoice("signature", `must have a recovery id of at most ${MAX_RECOVERY_ID}`);
    if (compact.hasHighS()) refuseInvoice("signature", "must be low-S");
    let recovered: Uint8Array;
    try {
        recovered = compact.addRecoveryBit(recoveryId).recoverPublicKey(digest).toBytes(true);
    } catch {
        refuseInvoice("signature", "must recover a public key");
    }
    // Fiber never compares the recovered key with the attribute, so it lets a flipped recovery id through.
    if (payeePublicKey !== undefined && compareBytes(recovered, payeePublicKey) !== 0) {
        refuseInvoice("signature", "must be by the payee key the invoice carries");
    }
}

/**
 * Reads a signed invoice string, refusing every string fiber's encoder would not have written for what it carries.
 * @param text The bech32m string.
 * @returns The invoice.
 */
export function decodeInvoice(text: string): Invoice {
    assertString("invoice", text);
    const { hrp, groups } = decodeInvoiceBech32m(text);
    const { currency, amountShannons } = parseHrp(hrp);
    if (groups[0] !== SIGNED_FLAG) refuseInvoice("flag", "must mark a signed invoice");
    if (groups.length <= 1 + INVOICE_SIGNATURE_GROUPS) refuseInvoice("invoice", "must carry a compressed stream and a signature");
    const compressed = invoiceGroupsToBytes(groups.slice(1, -INVOICE_SIGNATURE_GROUPS), "compressed");
    const signature = invoiceGroupsToBytes(groups.slice(-INVOICE_SIGNATURE_GROUPS), "signature");
    const molecule = arDecompress(compressed);
    // Fiber ignores what follows the end marker and the low bits of the last byte; the coder writes them one way.
    if (compareBytes(arEncompress(molecule), compressed) !== 0) refuseInvoice("compressed", "must be the stream fiber's coder writes");
    const data = decodeInvoiceData(molecule);
    const payee = data.attributes.find((attribute): attribute is PayeeAttribute => attribute.type === "payeePublicKey");
    verifySignature(signature, signedDigest(hrp, compressed), payee?.publicKey);
    return { currency, amountShannons, ...data, signature };
}
