import { MESSAGE_DIGEST_LENGTH, isDecimalShannons, isHexBytes, isPlainObject, isUnsignedInteger } from "../../common";
import { MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, NONCE_CONTEXTS } from "../../derivation";
import { CHANNEL_POLICY_RECORD_VERSION } from "../policy.constants";
import type { ChannelPolicyRecord } from "../policy.types";

const CONTEXTS: readonly string[] = NONCE_CONTEXTS;
const CANONICAL_DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;

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
 * Checks that a value maps known nonce contexts to commitment numbers within the chain.
 * @param value Value to check.
 * @returns Whether the value is a per-context counter map.
 */
function isContextCounterMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(
        ([context, counter]) => CONTEXTS.includes(context) && isUnsignedInteger(counter, MAX_COMMITMENT_NUMBER),
    );
}

/**
 * Checks that a value maps sign-once slot keys to the digest each slot signed.
 * @param value Value to check.
 * @returns Whether the value is a signed digest map.
 */
function isSignedDigestMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(([slot, digest]) => isSignSlot(slot) && isHexBytes(digest, MESSAGE_DIGEST_LENGTH));
}

/**
 * Checks that a key is a sign-once slot: a known context and a commitment number, separated by a colon.
 * @param value Key to check.
 * @returns Whether the key names a slot.
 */
function isSignSlot(value: string): boolean {
    const separator = value.indexOf(":");
    if (separator === -1) return false;
    const context = value.slice(0, separator);
    const commitmentNumber = value.slice(separator + 1);
    // Canonical decimal: one slot key per number.
    return (
        CONTEXTS.includes(context) && CANONICAL_DECIMAL_PATTERN.test(commitmentNumber) && Number(commitmentNumber) <= MAX_COMMITMENT_NUMBER
    );
}
