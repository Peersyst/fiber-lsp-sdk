import { equalBytes } from "@noble/curves/utils.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import type { CellOutput } from "../../common";
import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    MESSAGE_DIGEST_LENGTH,
    PAYMENT_HASH_LENGTH,
    RECOVERABLE_ECDSA_SIGNATURE_LENGTH,
    SCHNORR_SIGNATURE_LENGTH,
    TLC_DIRECTIONS,
    TLC_HASH_ALGORITHMS,
    TRUNCATED_PAYMENT_HASH_LENGTH,
    UINT32_MAX,
    UINT64_MAX,
    blake160,
    isCanonicalDecimal,
    isDecimalShannons,
    isHexBytes,
    isNonEmptyHexBytes,
    isNonEmptyString,
    isPlainObject,
    isPositiveDecimalShannons,
    isUnsignedInteger,
} from "../../common";
import { MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, MAX_INVOICE_INDEX, NONCE_CONTEXTS } from "../../derivation";
import {
    COMMITMENT_LOCK_LAYOUTS,
    readCommitmentLockLayout,
    readCommitmentLockSettled,
    readCommitmentLockSettlementHash,
    readSettlementBody,
    settlementTlcEntryLength,
} from "../../digest";
import { WIRE_HEX_PREFIX, decodeMoleculeCellOutput } from "../../wire";
import {
    CHANNEL_POLICY_RECORD_VERSION,
    CHANNEL_TERMS_PINS,
    FIRST_SIGHT_CHANNEL_PINS,
    MAX_REVOKED_VERSION,
    MAX_WATCHTOWER_SPENDS,
    PAYMENT_RECORD_VERSION,
    POLICY_VIEWS,
    SIGNING_LANES,
} from "../policy.constants";
import type {
    ChannelPolicyRecord,
    ChannelTermsPin,
    DebitIntentRecord,
    FirstSightChannelPin,
    HoldInvoicePolicyRecord,
    WatchtowerKeyPurpose,
    WatchtowerSpendRecord,
} from "../policy.types";
import { assertWatchtowerKeyPurpose } from "../watchtower-spend";

const CONTEXTS: readonly string[] = NONCE_CONTEXTS;
const LANES: readonly string[] = SIGNING_LANES;
const VIEWS: readonly string[] = POLICY_VIEWS;
const DIRECTIONS: readonly unknown[] = TLC_DIRECTIONS;
const HASH_ALGORITHMS: readonly unknown[] = TLC_HASH_ALGORITHMS;
const LOCK_LAYOUTS: readonly string[] = COMMITMENT_LOCK_LAYOUTS;
const MAX_UINT64_DIGITS = UINT64_MAX.toString().length;

const PIN_FORMS: Record<FirstSightChannelPin | ChannelTermsPin, (value: string) => boolean> = {
    fundingOutPoint: isOutPointPin,
    fundingCapacityShannons: isUint64Decimal,
    liquidCapacityShannons: isDecimalShannons,
    remoteFundingPubkey: (value) => isHexBytes(value, COMPRESSED_POINT_LENGTH),
    remoteTlcBasePubkey: (value) => isHexBytes(value, COMPRESSED_POINT_LENGTH),
    commitmentDelayEpoch: isUint64Decimal,
    commitmentFeeRate: isUint64Decimal,
    remoteReservedCkbShannons: isUint64Decimal,
    remoteCloseScript: isNonEmptyHexBytes,
    lockLayout: (value) => LOCK_LAYOUTS.includes(value),
};

/**
 * Checks that a value is a stored {@link ChannelPolicyRecord}, extra fields tolerated.
 * @param value Value to check.
 * @returns Whether the value is a valid channel policy record.
 */
export function isChannelPolicyRecord(value: unknown): value is ChannelPolicyRecord {
    if (!isPlainObject(value)) return false;
    return (
        value.version === CHANNEL_POLICY_RECORD_VERSION &&
        isNonEmptyString(value.channelId) &&
        isLaneCounterMap(value.lastSignedCommitmentNumbers) &&
        isSignedSessionMap(value.signedSessions) &&
        isNonceReuseMap(value.nonceReuse, value.signedSessions) &&
        isCommitmentHashMap(value.commitmentHashes) &&
        (value.previousRemoteCommitment === undefined ||
            isPreviousRemoteCommitment(value.previousRemoteCommitment, value.commitmentHashes)) &&
        isRevocationEvidenceList(value.revocations) &&
        isChannelPins(value.pins) &&
        isViewSnapshotPair(value.views) &&
        (value.watchtowerSpends === undefined ||
            isWatchtowerSpendList(value.watchtowerSpends, value.commitmentHashes, value.pins.lockLayout))
    );
}

/**
 * Checks that a value is a stored {@link DebitIntentRecord}, extra fields tolerated.
 * @param value Value to check.
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
 * Checks that a value is a stored {@link HoldInvoicePolicyRecord}, extra fields tolerated.
 * @param value Value to check.
 * @returns Whether the value is a valid hold invoice record.
 */
export function isHoldInvoicePolicyRecord(value: unknown): value is HoldInvoicePolicyRecord {
    if (!isPlainObject(value)) return false;
    return (
        value.version === PAYMENT_RECORD_VERSION &&
        isHexBytes(value.paymentHash, PAYMENT_HASH_LENGTH) &&
        isPositiveDecimalShannons(value.amountShannons) &&
        HASH_ALGORITHMS.includes(value.hashAlgorithm) &&
        isUnsignedInteger(value.invoiceIndex, MAX_INVOICE_INDEX) &&
        typeof value.released === "boolean" &&
        isChannelIndexSet(value.channelIndexes)
    );
}

/**
 * Checks that a value is a channel's pins.
 * @param value Value to check.
 * @returns Whether the value holds the pins.
 */
function isChannelPins(value: unknown): value is Record<string, unknown> {
    if (!isPlainObject(value)) return false;
    return (
        typeof value.fundedShannons === "string" &&
        isUint64Decimal(value.fundedShannons) &&
        isNonEmptyHexBytes(value.localCloseScript) &&
        isReserveByLayout(value.localReservedCkbShannons) &&
        value.udtTypeScript === null &&
        [...FIRST_SIGHT_CHANNEL_PINS, ...CHANNEL_TERMS_PINS].every((pin) => {
            const pinned = value[pin];
            return pinned === undefined || (typeof pinned === "string" && PIN_FORMS[pin](pinned));
        })
    );
}

/**
 * Checks that a value holds the device's reserve under each lock layout and no other key, each a u64 in canonical decimal.
 * @param value Value to check.
 * @returns Whether the value is a reserve-by-layout map.
 */
function isReserveByLayout(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return (
        Object.keys(value).length === COMMITMENT_LOCK_LAYOUTS.length &&
        COMMITMENT_LOCK_LAYOUTS.every((layout) => {
            const reserved = value[layout];
            return typeof reserved === "string" && isUint64Decimal(reserved);
        })
    );
}

/**
 * Checks that a value is an out point in its pin form, `<tx hash hex>:<index>`.
 * @param value Value to check.
 * @returns Whether the value is an out point pin.
 */
function isOutPointPin(value: string): boolean {
    const separator = value.indexOf(":");
    if (separator === -1) return false;
    const index = value.slice(separator + 1);
    return isHexBytes(value.slice(0, separator), HASH256_LENGTH) && isCanonicalDecimal(index) && Number(index) <= UINT32_MAX;
}

/**
 * Checks that a value is a u64 in canonical decimal.
 * @param value Value to check.
 * @returns Whether the value is one.
 */
function isUint64Decimal(value: string): boolean {
    return value.length <= MAX_UINT64_DIGITS && isCanonicalDecimal(value) && BigInt(value) <= UINT64_MAX;
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
        isViewTlcFullHash(value.fullPaymentHash, value.boundPaymentHash) &&
        isDecimalShannons(value.amountShannons) &&
        typeof value.expirySeconds === "string" &&
        isUint64Decimal(value.expirySeconds)
    );
}

/**
 * Checks that a view TLC's full payment hash is `null`, or the whole hash the bound one is the prefix of.
 * @param value Value to check.
 * @param boundPaymentHash The TLC's bound payment hash, already checked.
 * @returns Whether the value is a view TLC's full payment hash.
 */
function isViewTlcFullHash(value: unknown, boundPaymentHash: string): boolean {
    return value === null || (isHexBytes(value, PAYMENT_HASH_LENGTH) && value.startsWith(boundPaymentHash));
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
 * Checks that a value maps known signing lanes to commitment numbers within the chain.
 * @param value Value to check.
 * @returns Whether the value is a per-lane counter map.
 */
function isLaneCounterMap(value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(([lane, counter]) => LANES.includes(lane) && isCommitmentNumber(counter));
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

/**
 * Checks that a value maps served slots to the second session each served, never the first one again.
 * @param value Value to check.
 * @param signedSessions The record's sign-once registry.
 * @returns Whether the value is a nonce reuse log.
 */
function isNonceReuseMap(value: unknown, signedSessions: unknown): boolean {
    if (!isPlainObject(value) || !isPlainObject(signedSessions)) return false;
    return Object.entries(value).every(([slot, entry]) => {
        if (!isSignSlot(slot) || !isPlainObject(entry)) return false;
        const first = signedSessions[slot];
        return (
            isHexBytes(entry.sessionCommitment, MESSAGE_DIGEST_LENGTH) &&
            isHexBytes(entry.message, MESSAGE_DIGEST_LENGTH) &&
            typeof first === "string" &&
            first !== entry.sessionCommitment
        );
    });
}

/**
 * Checks that a value maps views to the last commitment signed in each.
 * @param value Value to check.
 * @returns Whether the value is a commitment hash map.
 */
function isCommitmentHashMap(value: unknown): value is Record<string, unknown> {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(([view, entry]) => VIEWS.includes(view) && isSignedCommitment(entry));
}

/**
 * Checks that a value is a signed commitment record.
 * @param value Value to check.
 * @returns Whether the value is one.
 */
function isSignedCommitment(value: unknown): boolean {
    if (!isPlainObject(value) || !isCommitmentNumber(value.commitmentNumber) || !isHexBytes(value.txHash, MESSAGE_DIGEST_LENGTH))
        return false;
    // Both absent from a commitment signed before the record kept them.
    if (value.source === undefined && value.settlementWitness === undefined) return true;
    return isCommitmentSource(value.source, value.settlementWitness);
}

/**
 * Checks that a value is the remote commitment signed before the record's last remote one.
 * @param value Value to check.
 * @param commitmentHashes The record's signed commitments, already checked.
 * @returns Whether the value is one.
 */
function isPreviousRemoteCommitment(value: unknown, commitmentHashes: Record<string, unknown>): boolean {
    if (!isPlainObject(value) || !isCommitmentNumber(value.commitmentNumber)) return false;
    const last = commitmentHashes.remote;
    return (
        isPlainObject(last) &&
        last.commitmentNumber === value.commitmentNumber + 1 &&
        isCommitmentSource(value.source, value.settlementWitness)
    );
}

/**
 * Checks that a value is a commitment's cell whose lock args commit the settlement body given.
 * @param value Value to check.
 * @param settlementWitness The settlement body recorded with it.
 * @returns Whether they match.
 */
function isCommitmentSource(value: unknown, settlementWitness: unknown): boolean {
    const output = readCommitmentLockCell(value, false);
    return output !== null && isCommittedSettlementBody(settlementWitness, output.lock.args);
}

/**
 * Reads a recorded cell that is a commitment lock's with no type and no data, the only cells the device signs a spend of.
 * @param value Value to check.
 * @param settled Whether it must be a remainder.
 * @returns Its output, or `null` when the value is no such cell.
 */
function readCommitmentLockCell(value: unknown, settled: boolean): CellOutput | null {
    if (!isPlainObject(value) || !isNonEmptyHexBytes(value.output) || value.outputData !== "") return null;
    try {
        const output = decodeMoleculeCellOutput({ value: WIRE_HEX_PREFIX + value.output, path: "output" });
        return output.type === null && readCommitmentLockSettled(output.lock.args) === settled ? output : null;
    } catch {
        return null;
    }
}

/**
 * Checks that a value is the settlement body a commitment lock's args commit.
 * @param value Value to check.
 * @param args The lock args, a commitment lock's.
 * @returns Whether it is.
 */
function isCommittedSettlementBody(value: unknown, args: Uint8Array): boolean {
    if (!isNonEmptyHexBytes(value)) return false;
    const body = hexToBytes(value);
    try {
        readSettlementBody(body, readCommitmentLockLayout(args));
    } catch {
        return false;
    }
    return equalBytes(blake160(body), readCommitmentLockSettlementHash(args));
}

/**
 * Checks that a value lists the watchtower spends claimed, one per request and one per commitment and unlock.
 * @param value Value to check.
 * @param commitmentHashes The record's signed commitments, already checked.
 * @param lockLayout The record's pinned lock layout, already checked, `undefined` before the pin.
 * @returns Whether the value is a watchtower spend list.
 */
function isWatchtowerSpendList(value: unknown, commitmentHashes: Record<string, unknown>, lockLayout: unknown): boolean {
    if (!Array.isArray(value) || value.length > MAX_WATCHTOWER_SPENDS) return false;
    const tlcEntryLengths = COMMITMENT_LOCK_LAYOUTS.filter((layout) => lockLayout === undefined || layout === lockLayout).map(
        settlementTlcEntryLength,
    );
    const requestIds = new Set<string>();
    const keys = new Set<string>();
    return value.every((entry: unknown) => {
        if (!isWatchtowerSpend(entry, commitmentHashes, tlcEntryLengths)) return false;
        const key = `${entry.view}:${entry.commitmentNumber}:${entry.tlcEntry ?? ""}`;
        if (requestIds.has(entry.requestId) || keys.has(key)) return false;
        requestIds.add(entry.requestId);
        keys.add(key);
        return true;
    });
}

/**
 * Checks that a value is a watchtower spend record.
 * @param value Value to check.
 * @param commitmentHashes The record's signed commitments, already checked.
 * @param tlcEntryLengths The lengths a TLC entry may have under the record's layout.
 * @returns Whether the value is a watchtower spend.
 */
function isWatchtowerSpend(
    value: unknown,
    commitmentHashes: Record<string, unknown>,
    tlcEntryLengths: number[],
): value is WatchtowerSpendRecord {
    if (!isPlainObject(value)) return false;
    return (
        isHexBytes(value.requestId, HASH256_LENGTH) &&
        isWatchtowerKeyPurpose(value.purpose) &&
        typeof value.view === "string" &&
        VIEWS.includes(value.view) &&
        commitmentHashes[value.view] !== undefined &&
        isCommitmentNumber(value.commitmentNumber) &&
        (value.tlcEntry === null
            ? value.purpose.kind === "settlement"
            : value.purpose.kind === "tlc" && tlcEntryLengths.some((length) => isHexBytes(value.tlcEntry, length))) &&
        isHexBytes(value.txHash, HASH256_LENGTH) &&
        (value.remainder === null || readCommitmentLockCell(value.remainder, true) !== null) &&
        (value.signature === null || isHexBytes(value.signature, RECOVERABLE_ECDSA_SIGNATURE_LENGTH)) &&
        // Fiber applies a signature the device recorded before submitting it.
        typeof value.applied === "boolean" &&
        (!value.applied || value.signature !== null)
    );
}

/**
 * Checks that a value is a watchtower key purpose.
 * @param value Value to check.
 * @returns Whether it is one.
 */
function isWatchtowerKeyPurpose(value: unknown): value is WatchtowerKeyPurpose {
    try {
        assertWatchtowerKeyPurpose("purpose", value);
        return true;
    } catch {
        return false;
    }
}

/**
 * Checks that a value lists revocation evidence in strictly ascending version order.
 * @param value Value to check.
 * @returns Whether the value is a revocation evidence list.
 */
function isRevocationEvidenceList(value: unknown): boolean {
    if (!Array.isArray(value)) return false;
    let previous = -1;
    return value.every((entry: unknown) => {
        if (!isPlainObject(entry) || !isUnsignedInteger(entry.version, MAX_REVOKED_VERSION) || entry.version <= previous) return false;
        previous = entry.version;
        return entry.forRemote === true && isHexBytes(entry.signature, SCHNORR_SIGNATURE_LENGTH);
    });
}

/**
 * Checks that a value is a commitment number within the chain.
 * @param value Value to check.
 * @returns Whether the value is one.
 */
function isCommitmentNumber(value: unknown): value is number {
    return isUnsignedInteger(value, MAX_COMMITMENT_NUMBER);
}
