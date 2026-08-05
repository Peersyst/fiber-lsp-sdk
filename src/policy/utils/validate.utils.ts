import { isHexBytes, isUnsignedInteger } from "../../common";
import { MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, NONCE_CONTEXTS } from "../../derivation";
import { CHANNEL_POLICY_RECORD_VERSION, MAX_AMOUNT_SHANNONS, MESSAGE_DIGEST_LENGTH } from "../policy.constants";
import type { ChannelPolicyRecord } from "../policy.types";

const CONTEXTS: readonly string[] = NONCE_CONTEXTS;
const DECIMAL_SHANNONS_PATTERN = /^(0|[1-9][0-9]*)$/;
// Digits of u128 max; length-checked before converting to BigInt.
const MAX_AMOUNT_DIGITS = 39;

/**
 * Checks that a value is an amount in decimal shannons: canonical digits within fiber's u128 range, no sign, no leading zeros.
 * @param value Value to check.
 * @returns Whether the value is a decimal shannons string.
 */
export function isDecimalShannons(value: unknown): value is string {
    return (
        typeof value === "string" &&
        value.length <= MAX_AMOUNT_DIGITS &&
        DECIMAL_SHANNONS_PATTERN.test(value) &&
        BigInt(value) <= MAX_AMOUNT_SHANNONS
    );
}

/**
 * Checks that a value has the exact shape of a stored {@link ChannelPolicyRecord}. Unknown extra fields are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid channel policy record.
 */
export function isChannelPolicyRecord(value: unknown): value is ChannelPolicyRecord {
    if (!isPlainObject(value)) return false;
    return (
        value.version === CHANNEL_POLICY_RECORD_VERSION &&
        isUnsignedInteger(value.channelIndex, MAX_CHANNEL_INDEX) &&
        isContextCounterMap(value.lastSignedCommitmentNumbers) &&
        isSignedDigestMap(value.signedDigests) &&
        isUnsignedInteger(value.lastStateVersion, Number.MAX_SAFE_INTEGER) &&
        isDecimalShannons(value.localBalanceShannons) &&
        Array.isArray(value.pendingDebitsShannons) &&
        value.pendingDebitsShannons.every(isDecimalShannons)
    );
}

/**
 * Asserts that a value has the exact shape of a stored {@link ChannelPolicyRecord}.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertChannelPolicyRecord(name: string, value: unknown): void {
    if (!isChannelPolicyRecord(value)) {
        throw new TypeError(`${name} is not a valid channel policy record`);
    }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isContextCounterMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(
        ([context, counter]) => CONTEXTS.includes(context) && isUnsignedInteger(counter, MAX_COMMITMENT_NUMBER),
    );
}

function isSignedDigestMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(([slot, digest]) => isSignSlot(slot) && isHexBytes(digest, MESSAGE_DIGEST_LENGTH));
}

function isSignSlot(value: string): boolean {
    const separator = value.indexOf(":");
    if (separator === -1) return false;
    const context = value.slice(0, separator);
    const commitmentNumber = value.slice(separator + 1);
    // Canonical decimal: one slot key per number.
    return (
        CONTEXTS.includes(context) && DECIMAL_SHANNONS_PATTERN.test(commitmentNumber) && Number(commitmentNumber) <= MAX_COMMITMENT_NUMBER
    );
}
