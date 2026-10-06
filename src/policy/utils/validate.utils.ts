import {
    MESSAGE_DIGEST_LENGTH,
    PAYMENT_HASH_LENGTH,
    TLC_DIRECTIONS,
    TLC_HASH_ALGORITHMS,
    TRUNCATED_PAYMENT_HASH_LENGTH,
    UINT64_MAX,
    isCanonicalDecimal,
    isDecimalShannons,
    isHexBytes,
    isNonEmptyString,
    isPlainObject,
    isUnsignedInteger,
} from "../../common";
import { MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, NONCE_CONTEXTS } from "../../derivation";
import { CHANNEL_POLICY_RECORD_VERSION, PAYMENT_RECORD_VERSION, POLICY_VIEWS } from "../policy.constants";
import type { ChannelPolicyRecord, DebitIntentRecord, HoldInvoicePolicyRecord } from "../policy.types";

const CONTEXTS: readonly string[] = NONCE_CONTEXTS;
const DIRECTIONS: readonly unknown[] = TLC_DIRECTIONS;
const HASH_ALGORITHMS: readonly unknown[] = TLC_HASH_ALGORITHMS;
const MAX_EXPIRY_DIGITS = UINT64_MAX.toString().length;

/**
 * Checks that a value has the exact shape of a stored {@link ChannelPolicyRecord}. Unknown extra fields are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid channel policy record.
 */
export function isChannelPolicyRecord(value: unknown): value is ChannelPolicyRecord {
    if (!isPlainObject(value)) return false;
    return (
        value.version === CHANNEL_POLICY_RECORD_VERSION &&
        isNonEmptyString(value.channelId) &&
        isContextCounterMap(value.lastSignedCommitmentNumbers) &&
        isSignedSessionMap(value.signedSessions) &&
        isUnsignedInteger(value.lastStateVersion, Number.MAX_SAFE_INTEGER) &&
        isViewSnapshotPair(value.views)
    );
}

/**
 * Checks that a value has the exact shape of a stored {@link DebitIntentRecord}. Unknown extra fields are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid debit intent record.
 */
export function isDebitIntentRecord(value: unknown): value is DebitIntentRecord {
    if (!isPlainObject(value)) return false;
    return (
        value.version === PAYMENT_RECORD_VERSION &&
        isHexBytes(value.paymentHash, PAYMENT_HASH_LENGTH) &&
        isDecimalShannons(value.maxShannons) &&
        typeof value.open === "boolean" &&
        isChannelIndexSet(value.channelIndexes)
    );
}

/**
 * Checks that a value has the exact shape of a stored {@link HoldInvoicePolicyRecord}. Unknown extra fields are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid hold invoice record.
 */
export function isHoldInvoicePolicyRecord(value: unknown): value is HoldInvoicePolicyRecord {
    if (!isPlainObject(value)) return false;
    return (
        value.version === PAYMENT_RECORD_VERSION &&
        isHexBytes(value.paymentHash, PAYMENT_HASH_LENGTH) &&
        isDecimalShannons(value.amountShannons) &&
        HASH_ALGORITHMS.includes(value.hashAlgorithm) &&
        typeof value.released === "boolean" &&
        isChannelIndexSet(value.channelIndexes)
    );
}

/**
 * Checks that a value holds one snapshot per view, tolerating extra keys.
 * @param value Value to check.
 * @returns Whether the value holds both view snapshots.
 */
function isViewSnapshotPair(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return POLICY_VIEWS.every((view) => isViewSnapshot(value[view]));
}

/**
 * Checks that a value is one view's snapshot.
 * @param value Value to check.
 * @returns Whether the value is a view snapshot.
 */
function isViewSnapshot(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return (
        isDecimalShannons(value.exposureShannons) &&
        Array.isArray(value.tlcs) &&
        value.tlcs.every(isViewTlc) &&
        isAmountByHashMap(value.chargedShannons) &&
        isAmountByHashMap(value.creditedShannons)
    );
}

/**
 * Checks that a value is a TLC as a view snapshot lists it.
 * @param value Value to check.
 * @returns Whether the value is a view TLC.
 */
function isViewTlc(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return (
        DIRECTIONS.includes(value.direction) &&
        HASH_ALGORITHMS.includes(value.hashAlgorithm) &&
        isHexBytes(value.boundPaymentHash, TRUNCATED_PAYMENT_HASH_LENGTH) &&
        isDecimalShannons(value.amountShannons) &&
        typeof value.expirySeconds === "string" &&
        value.expirySeconds.length <= MAX_EXPIRY_DIGITS &&
        isCanonicalDecimal(value.expirySeconds) &&
        BigInt(value.expirySeconds) <= UINT64_MAX
    );
}

/**
 * Checks that a value maps bound payment hashes to amounts.
 * @param value Value to check.
 * @returns Whether the value is an amount-by-hash map.
 */
function isAmountByHashMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(([hash, amount]) => isHexBytes(hash, TRUNCATED_PAYMENT_HASH_LENGTH) && isDecimalShannons(amount));
}

/**
 * Checks that a value is a list of distinct channel indexes.
 * @param value Value to check.
 * @returns Whether the value is a channel index set.
 */
function isChannelIndexSet(value: unknown): boolean {
    return (
        Array.isArray(value) && value.every((index) => isUnsignedInteger(index, MAX_CHANNEL_INDEX)) && new Set(value).size === value.length
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
 * Checks that a value maps sign-once slot keys to the commitment of the session each slot served.
 * @param value Value to check.
 * @returns Whether the value is a signed session map.
 */
function isSignedSessionMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(([slot, commitment]) => isSignSlot(slot) && isHexBytes(commitment, MESSAGE_DIGEST_LENGTH));
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
    return CONTEXTS.includes(context) && isCanonicalDecimal(commitmentNumber) && Number(commitmentNumber) <= MAX_COMMITMENT_NUMBER;
}
