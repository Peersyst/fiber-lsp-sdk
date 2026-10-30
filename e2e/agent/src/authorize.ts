import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { HASH_ALGORITHMS } from "./agent.constants";
import { AgentRequestError } from "./agent.error";
import type { AgentAuthorization, AgentHashAlgorithm } from "./agent.types";
import { ckbBlake2b } from "./ckb-hash";
import { readJsonObject } from "./agent.utils";
import { readScriptJson } from "./open-params";

const AUTHORIZATION_TYPES: readonly AgentAuthorization["type"][] = ["Invoice", "ReleasePreimage", "Close", "Watchtower"];
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

/**
 * Reads a `POST /authorize` body into one of the four authorizations, ignoring unknown fields as fiber's agent does.
 * @param body The parsed body.
 * @returns The authorization, hashes as `0x` lowercase hex.
 */
export function readAuthorization(body: unknown): AgentAuthorization {
    const fields = readJsonObject(body, "body");
    const type = readEnum(fields.type, AUTHORIZATION_TYPES, "type");
    const channelId = readHash256(fields.channel_id, "channel_id");
    switch (type) {
        case "Invoice": {
            const terms = readJsonObject(fields.terms, "terms");
            const paymentHash = readHash256(terms.payment_hash, "terms.payment_hash");
            const hashAlgorithm = readEnum(terms.hash_algorithm, HASH_ALGORITHMS, "terms.hash_algorithm");
            if (typeof terms.inbound !== "boolean") throw new AgentRequestError("terms.inbound must be a boolean");
            readJsonInteger(terms.amount, 0, "terms.amount");
            readJsonInteger(terms.expires_at_ms, 0, "terms.expires_at_ms");
            readJsonInteger(terms.min_tlc_expiry_delta_ms, 0, "terms.min_tlc_expiry_delta_ms");
            readJsonInteger(terms.max_tlc_expiry_ms, 0, "terms.max_tlc_expiry_ms");
            const preimage = readHash256(fields.preimage, "preimage");
            // As fiber's `authorize_invoice`.
            if (!terms.inbound) throw new AgentRequestError("terms.inbound must be true: an Invoice authorizes an incoming payment");
            assertPreimageMatches(paymentHash, preimage, hashAlgorithm);
            return { type: "Invoice", channelId, preimage, paymentHash, hashAlgorithm };
        }
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
 * Refuses a preimage that does not hash to the payment hash under the invoice's algorithm.
 * @param paymentHash The payment hash, 32 bytes of hex, with or without `0x`.
 * @param preimage The preimage, 32 bytes of hex, with or without `0x`.
 * @param algorithm The invoice's hash algorithm.
 */
export function assertPreimageMatches(paymentHash: string, preimage: string, algorithm: AgentHashAlgorithm): void {
    const preimageBytes = hexToBytes(readHash256(preimage, "preimage").slice(2));
    const digest = algorithm === "ckb_hash" ? ckbBlake2b(preimageBytes) : sha256(preimageBytes);
    if (`0x${bytesToHex(digest)}` !== readHash256(paymentHash, "payment_hash")) {
        throw new AgentRequestError(`preimage does not hash to payment_hash under ${algorithm}`);
    }
}
