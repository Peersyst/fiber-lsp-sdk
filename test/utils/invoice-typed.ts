import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { TlcHashAlgorithm } from "../../src/common";
import type { Invoice, InvoiceAttribute, InvoiceCurrency, UnsignedInvoice } from "../../src/invoice";
import { toScript } from "./digest-inputs";
import type { InvoiceAttributeVector, InvoiceCaseVector, InvoiceValuesVector } from "./invoice-vectors";
import { HASH_ALGORITHM_WIRE } from "./wire-requests";

function hashAlgorithmOf(wire: string): TlcHashAlgorithm {
    const found = Object.entries(HASH_ALGORITHM_WIRE).find(([, spelling]) => spelling === wire);
    if (found === undefined) throw new Error(`the vectors carry an unknown hash algorithm: ${wire}`);
    return found[0] as TlcHashAlgorithm;
}

export function toInvoiceAttribute(vector: InvoiceAttributeVector): InvoiceAttribute {
    if (vector.type === "udt_script") return { type: "udtScript", script: toScript(vector.value) };
    const { value } = vector;
    switch (vector.type) {
        case "expiry_time":
            return { type: "expiryTime", seconds: BigInt(value) };
        case "final_htlc_timeout":
            return { type: "finalHtlcTimeout", milliseconds: BigInt(value) };
        case "final_htlc_minimum_expiry_delta":
            return { type: "finalHtlcMinimumExpiryDelta", milliseconds: BigInt(value) };
        case "description":
            return { type: "description", text: value };
        case "fallback_addr":
            return { type: "fallbackAddr", address: value };
        case "feature":
            return { type: "feature", bits: hexToBytes(value) };
        case "payee_public_key":
            return { type: "payeePublicKey", publicKey: hexToBytes(value) };
        case "hash_algorithm":
            return { type: "hashAlgorithm", algorithm: hashAlgorithmOf(value) };
        case "payment_secret":
            return { type: "paymentSecret", secret: hexToBytes(value) };
    }
}

export function toInvoiceAttributeVector(attribute: InvoiceAttribute): InvoiceAttributeVector {
    switch (attribute.type) {
        case "expiryTime":
            return { type: "expiry_time", value: attribute.seconds.toString() };
        case "finalHtlcTimeout":
            return { type: "final_htlc_timeout", value: attribute.milliseconds.toString() };
        case "finalHtlcMinimumExpiryDelta":
            return { type: "final_htlc_minimum_expiry_delta", value: attribute.milliseconds.toString() };
        case "description":
            return { type: "description", value: attribute.text };
        case "fallbackAddr":
            return { type: "fallback_addr", value: attribute.address };
        case "feature":
            return { type: "feature", value: bytesToHex(attribute.bits) };
        case "udtScript":
            return {
                type: "udt_script",
                value: {
                    code_hash: bytesToHex(attribute.script.codeHash),
                    hash_type: attribute.script.hashType,
                    args: bytesToHex(attribute.script.args),
                },
            };
        case "payeePublicKey":
            return { type: "payee_public_key", value: bytesToHex(attribute.publicKey) };
        case "hashAlgorithm":
            return { type: "hash_algorithm", value: HASH_ALGORITHM_WIRE[attribute.algorithm] as string };
        case "paymentSecret":
            return { type: "payment_secret", value: bytesToHex(attribute.secret) };
    }
}

export function toUnsignedInvoice(vector: InvoiceValuesVector): UnsignedInvoice {
    return {
        currency: vector.currency as InvoiceCurrency,
        amountShannons: vector.amount,
        timestampMs: BigInt(vector.timestamp),
        paymentHash: hexToBytes(vector.payment_hash),
        attributes: vector.attrs.map(toInvoiceAttribute),
    };
}

export function toInvoiceValuesVector(invoice: UnsignedInvoice): InvoiceValuesVector {
    return {
        currency: invoice.currency,
        amount: invoice.amountShannons,
        timestamp: invoice.timestampMs.toString(),
        payment_hash: bytesToHex(invoice.paymentHash),
        attrs: invoice.attributes.map(toInvoiceAttributeVector),
    };
}

export function toInvoice(vector: InvoiceCaseVector): Invoice {
    if (vector.signature === null) throw new Error(`the vector "${vector.name}" is unsigned`);
    return { ...toUnsignedInvoice(vector.values), signature: hexToBytes(vector.signature) };
}
