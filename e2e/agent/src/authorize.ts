import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { HASH_ALGORITHMS } from "./agent.constants";
import { AgentRequestError } from "./agent.error";
import type { AgentAuthorization, AgentHashAlgorithm, AgentPaymentTerms } from "./agent.types";
import { ckbBlake2b } from "./ckb-hash";
import { readJsonObject } from "./agent.utils";
import { readScriptJson } from "./open-params";

const AUTHORIZATION_TYPES: readonly AgentAuthorization["type"][] = [
    "Invoice",
    "Payment",
    "Fulfillment",
    "ReleasePreimage",
    "Close",
    "Watchtower",
];
const PREIMAGE_TARGETS = ["Invoice", "Watchtower"] as const;

/**
 * Reads a 32-byte hash or preimage, with or without `0x`.
 * @param value The value read.
 * @param field Where it sits, for the refusal.
 * @returns The value as `0x` lowercase hex.
 */
function readHash256(value: unknown, field: string): string {
    if (typeof value !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(value)) throw new AgentRequestError(`${field} must be 32 bytes of hex`);
    return `0x${value.slice(value.length - 64).toLowerCase()}`;
}

/**
 * Reads a JSON integer no larger than JavaScript holds exactly.
 * @param value The value read.
 * @param min The smallest value accepted.
 * @param field Where it sits, for the refusal.
 * @returns The integer.
 */
function readJsonInteger(value: unknown, min: number, field: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min) {
        throw new AgentRequestError(`${field} must be an integer from ${min} up`);
    }
    return value;
}

/**
 * Reads an enum value, its spelling exact.
 * @param value The value read.
 * @param allowed The spellings accepted.
 * @param field Where it sits, for the refusal.
 * @returns The value.
 */
function readEnum<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
    const found = allowed.find((known) => known === value);
    if (found === undefined) throw new AgentRequestError(`${field} must be one of ${allowed.join(", ")}`);
    return found;
}

type PaymentTerms = {
    paymentHash: string;
    hashAlgorithm: AgentHashAlgorithm;
    inbound: boolean;
    amount: number;
    expiresAtMs: number;
    minTlcExpiryDeltaMs: number;
    maxTlcExpiryMs: number;
};

/**
 * Reads the `terms` of an `Invoice` or a `Payment`, fiber's `PaymentAuthorization`, field by field.
 * @param value The value read.
 * @returns The terms, the hash as `0x` lowercase hex.
 */
function readPaymentTerms(value: unknown): PaymentTerms {
    const terms = readJsonObject(value, "terms");
    const paymentHash = readHash256(terms.payment_hash, "terms.payment_hash");
    const hashAlgorithm = readEnum(terms.hash_algorithm, HASH_ALGORITHMS, "terms.hash_algorithm");
    if (typeof terms.inbound !== "boolean") throw new AgentRequestError("terms.inbound must be a boolean");
    return {
        paymentHash,
        hashAlgorithm,
        inbound: terms.inbound,
        amount: readJsonInteger(terms.amount, 0, "terms.amount"),
        expiresAtMs: readJsonInteger(terms.expires_at_ms, 0, "terms.expires_at_ms"),
        minTlcExpiryDeltaMs: readJsonInteger(terms.min_tlc_expiry_delta_ms, 0, "terms.min_tlc_expiry_delta_ms"),
        maxTlcExpiryMs: readJsonInteger(terms.max_tlc_expiry_ms, 0, "terms.max_tlc_expiry_ms"),
    };
}

/**
 * Refuses terms fiber's `CommitmentState::authorize` refuses, with its message (d8dd6d28 `fiber-lsp-sdk/src/commitment.rs:255-260`).
 * @param terms The terms.
 */
function assertPaymentBounds(terms: PaymentTerms): void {
    if (terms.amount === 0 || terms.minTlcExpiryDeltaMs === 0 || terms.maxTlcExpiryMs <= terms.expiresAtMs) {
        throw new AgentRequestError("invalid payment amount or expiry bounds");
    }
}

/**
 * Writes the terms as an authorization keeps them, its direction left to its type.
 * @param terms The terms read.
 * @returns The terms, amounts and times as decimal strings.
 */
function termsRecord(terms: PaymentTerms): AgentPaymentTerms {
    return {
        paymentHash: terms.paymentHash,
        hashAlgorithm: terms.hashAlgorithm,
        amountShannons: terms.amount.toString(),
        expiresAtMs: terms.expiresAtMs.toString(),
        minTlcExpiryDeltaMs: terms.minTlcExpiryDeltaMs.toString(),
        maxTlcExpiryMs: terms.maxTlcExpiryMs.toString(),
    };
}

/**
 * Reads a `POST /authorize` body, ignoring unknown fields as fiber's agent does.
 * @param body The parsed body.
 * @returns The authorization, hashes as `0x` lowercase hex.
 */
export function readAuthorization(body: unknown): AgentAuthorization {
    const fields = readJsonObject(body, "body");
    const type = readEnum(fields.type, AUTHORIZATION_TYPES, "type");
    const channelId = readHash256(fields.channel_id, "channel_id");
    switch (type) {
        case "Invoice": {
            const terms = readPaymentTerms(fields.terms);
            const { paymentHash, hashAlgorithm } = terms;
            const preimage = readHash256(fields.preimage, "preimage");
            // As fiber's `authorize_invoice`.
            if (!terms.inbound) throw new AgentRequestError("terms.inbound must be true: an Invoice authorizes an incoming payment");
            assertPreimageMatches(paymentHash, preimage, hashAlgorithm);
            assertPaymentBounds(terms);
            return { type: "Invoice", channelId, preimage, ...termsRecord(terms) };
        }
        case "Payment": {
            const terms = readPaymentTerms(fields.terms);
            // As fiber's `authorize_payment` (d8dd6d28 `fiber-lsp-sdk/src/signer.rs:622-633`).
            if (terms.inbound) throw new AgentRequestError("inbound authorization requires authorize_invoice and a matching preimage");
            assertPaymentBounds(terms);
            return { type: "Payment", channelId, ...termsRecord(terms) };
        }
        case "Fulfillment":
            return {
                type: "Fulfillment",
                channelId,
                paymentHash: readHash256(fields.payment_hash, "payment_hash"),
                preimage: readHash256(fields.preimage, "preimage"),
            };
        case "ReleasePreimage":
            return {
                type: "ReleasePreimage",
                channelId,
                paymentHash: readHash256(fields.payment_hash, "payment_hash"),
                preimage: readHash256(fields.preimage, "preimage"),
                target: readEnum(fields.target, PREIMAGE_TARGETS, "target"),
            };
        case "Close":
            return {
                type: "Close",
                channelId,
                localScript: readScriptJson(fields.local_script, "local_script"),
                remoteScript: readScriptJson(fields.remote_script, "remote_script"),
                localFeeRate: readJsonInteger(fields.local_fee_rate, 0, "local_fee_rate").toString(),
                remoteFeeRate: readJsonInteger(fields.remote_fee_rate, 0, "remote_fee_rate").toString(),
            };
        case "Watchtower":
            return {
                type: "Watchtower",
                channelId,
                destination: readScriptJson(fields.destination, "destination"),
                maxFeeShannons: readJsonInteger(fields.max_fee, 1, "max_fee").toString(),
            };
    }
}

/**
 * Tells whether a preimage hashes to a payment hash under an algorithm.
 * @param paymentHash The payment hash, 32 bytes of hex, with or without `0x`.
 * @param preimage The preimage, 32 bytes of hex, with or without `0x`.
 * @param algorithm The hash algorithm.
 * @returns Whether it does.
 */
export function preimageMatches(paymentHash: string, preimage: string, algorithm: AgentHashAlgorithm): boolean {
    const preimageBytes = hexToBytes(readHash256(preimage, "preimage").slice(2));
    const digest = algorithm === "ckb_hash" ? ckbBlake2b(preimageBytes) : sha256(preimageBytes);
    return `0x${bytesToHex(digest)}` === readHash256(paymentHash, "payment_hash");
}

/**
 * Refuses a preimage that does not hash to the payment hash under the invoice's algorithm.
 * @param paymentHash The payment hash, 32 bytes of hex, with or without `0x`.
 * @param preimage The preimage, 32 bytes of hex, with or without `0x`.
 * @param algorithm The invoice's hash algorithm.
 */
export function assertPreimageMatches(paymentHash: string, preimage: string, algorithm: AgentHashAlgorithm): void {
    if (!preimageMatches(paymentHash, preimage, algorithm)) {
        throw new AgentRequestError(`preimage does not hash to payment_hash under ${algorithm}`);
    }
}
