import { bytesToHex } from "@noble/hashes/utils.js";
import { HASH256_LENGTH, UINT128_MAX, UINT64_MAX, moleculeScript } from "../../src/common";
import type { Invoice, InvoiceAttribute, InvoiceCurrency } from "../../src/invoice";
import { bytesToInvoiceGroups } from "../../src/invoice/bech32m";
import { encodeHexBytes, encodeUintHex } from "../../src/wire";
import { hashAlgorithmWire } from "./wire-spellings";

// `feature_bit_name` (`fiber-types/src/protocol.rs:240-249`): each base bit odd and optional, the even bit below it required.
const FEATURE_BIT_NAMES = [
    "GOSSIP_QUERIES_REQUIRED",
    "GOSSIP_QUERIES_OPTIONAL",
    "BASIC_MPP_REQUIRED",
    "BASIC_MPP_OPTIONAL",
    "TRAMPOLINE_ROUTING_REQUIRED",
    "TRAMPOLINE_ROUTING_OPTIONAL",
    "ONCHAIN_FULL_PAYMENT_HASH_REQUIRED",
    "ONCHAIN_FULL_PAYMENT_HASH_OPTIONAL",
];

export type InvoiceJsonAttribute = Record<string, string | string[]>;

// Fiber's JSON `CkbInvoice` (`fiber-json-types/src/invoice.rs:49-118`).
export type InvoiceJson = {
    currency: InvoiceCurrency;
    amount: string | null;
    signature: string;
    data: { timestamp: string; payment_hash: string; attrs: InvoiceJsonAttribute[] };
};

// As fiber converts its invoice for the RPC (`fiber-json-types/src/convert.rs:488-545`): the signature its five-bit groups, one
// byte each, in bare hex.
export function invoiceJson(invoice: Invoice): InvoiceJson {
    return {
        currency: invoice.currency,
        amount: invoice.amountShannons === null ? null : encodeUintHex("amount", BigInt(invoice.amountShannons), UINT128_MAX),
        signature: bytesToHex(Uint8Array.from(bytesToInvoiceGroups(invoice.signature))),
        data: {
            timestamp: encodeUintHex("timestamp", invoice.timestampMs, UINT128_MAX),
            payment_hash: encodeHexBytes("paymentHash", invoice.paymentHash, HASH256_LENGTH),
            attrs: invoice.attributes.map(attributeJson),
        },
    };
}

function attributeJson(attribute: InvoiceAttribute): InvoiceJsonAttribute {
    switch (attribute.type) {
        case "finalHtlcTimeout":
            return { final_htlc_timeout: encodeUintHex("finalHtlcTimeout", attribute.milliseconds, UINT64_MAX) };
        case "finalHtlcMinimumExpiryDelta":
            return { final_htlc_minimum_expiry_delta: encodeUintHex("finalHtlcMinimumExpiryDelta", attribute.milliseconds, UINT64_MAX) };
        // `duration_hex`, in seconds.
        case "expiryTime":
            return { expiry_time: encodeUintHex("expiryTime", attribute.seconds, UINT64_MAX) };
        case "description":
            return { description: attribute.text };
        case "fallbackAddr":
            return { fallback_addr: attribute.address };
        case "udtScript":
            return { udt_script: `0x${bytesToHex(moleculeScript(attribute.script))}` };
        case "payeePublicKey":
            return { payee_public_key: bytesToHex(attribute.publicKey) };
        case "hashAlgorithm":
            return { hash_algorithm: hashAlgorithmWire(attribute.algorithm) };
        case "feature":
            return { feature: featureNames(attribute.bits) };
        case "paymentSecret":
            return { payment_secret: `0x${bytesToHex(attribute.secret)}` };
        case "trampolineRouteHint":
            return { trampoline_route_hint: bytesToHex(attribute.nodeId) };
    }
}

// `enabled_features_names` (`fiber-types/src/protocol.rs:311-323`): bit `i` is bit `i % 8` of byte `i / 8`.
function featureNames(bits: Uint8Array): string[] {
    const names: string[] = [];
    for (let bit = 0; bit < bits.length * 8; bit++) {
        if ((((bits[bit >> 3] ?? 0) >> (bit % 8)) & 1) === 1) names.push(FEATURE_BIT_NAMES[bit] ?? "Unknown Feature");
    }
    return names;
}
