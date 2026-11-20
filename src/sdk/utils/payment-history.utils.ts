import {
    PAYMENT_HASH_LENGTH,
    isDecimalShannons,
    isHexBytes,
    isNonEmptyString,
    isPlainObject,
    isPositiveDecimalShannons,
    isUnsignedInteger,
} from "../../common";
import { isWireHex } from "../../wire";
import { PAYMENT_HISTORY_RECORD_VERSION, SDK_PAYMENT_DIRECTIONS, SDK_PAYMENT_RECORD_STATUSES } from "../sdk.constants";
import type { PaymentHistoryIndex, PaymentHistoryIndexEntry, SdkPaymentRecord, StoredPaymentRecord } from "../sdk.types";

export type PaymentHistorySend = Pick<SdkPaymentRecord, "paymentHashHex" | "amountShannons" | "invoice" | "description"> & {
    maxFeeShannons: string;
};

export type PaymentHistoryReceive = Pick<SdkPaymentRecord, "paymentHashHex" | "amountShannons" | "invoice" | "description">;

export type PaymentHistoryOutcome = { status: "completed"; feeShannons: string } | { status: "failed"; reason: string };

/**
 * Checks that a value has the exact shape of a stored payment record, its fields consistent with its status; extras are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid payment record.
 */
export function isStoredPaymentRecord(value: unknown): value is StoredPaymentRecord {
    if (!isPlainObject(value) || value.version !== PAYMENT_HISTORY_RECORD_VERSION) return false;
    const { paymentHashHex, direction, status, amountShannons, invoice, description, maxFeeShannons, feeShannons } = value;
    const { failedReason, createdAtMs, settledAtMs } = value;
    if (!isWireHex(paymentHashHex, PAYMENT_HASH_LENGTH)) return false;
    if (!isOneOf(SDK_PAYMENT_DIRECTIONS, direction) || !isOneOf(SDK_PAYMENT_RECORD_STATUSES, status)) return false;
    if (!isPositiveDecimalShannons(amountShannons) || !isNonEmptyString(invoice)) return false;
    if (description !== null && typeof description !== "string") return false;
    if (direction === "send" ? !isDecimalShannons(maxFeeShannons) : maxFeeShannons !== null) return false;
    if (!isUnsignedInteger(createdAtMs, Number.MAX_SAFE_INTEGER)) return false;
    if (status === "pending") return feeShannons === null && failedReason === null && settledAtMs === null;
    if (!isUnsignedInteger(settledAtMs, Number.MAX_SAFE_INTEGER)) return false;
    if (status === "failed") return feeShannons === null && typeof failedReason === "string";
    return failedReason === null && (direction === "send" ? isDecimalShannons(feeShannons) : feeShannons === "0");
}

/**
 * Asserts that a value has the exact shape of a stored payment record.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertStoredPaymentRecord(name: string, value: unknown): asserts value is StoredPaymentRecord {
    if (!isStoredPaymentRecord(value)) throw new TypeError(`${name} is not a valid payment record`);
}

/**
 * Checks that a value has the exact shape of the history's index: unique hashes, newest first, ties by hash; extras are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid index.
 */
export function isPaymentHistoryIndex(value: unknown): value is PaymentHistoryIndex {
    if (!isPlainObject(value) || value.version !== PAYMENT_HISTORY_RECORD_VERSION || !Array.isArray(value.entries)) return false;
    const entries: unknown[] = value.entries;
    if (!entries.every(isIndexEntry)) return false;
    const valid = entries as PaymentHistoryIndexEntry[];
    if (new Set(valid.map(({ paymentHash }) => paymentHash)).size !== valid.length) return false;
    return valid.every((entry, at) => {
        const next = valid[at + 1];
        return next === undefined || compareIndexEntries(entry, next) < 0;
    });
}

/**
 * Asserts that a value has the exact shape of the history's index.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertPaymentHistoryIndex(name: string, value: unknown): asserts value is PaymentHistoryIndex {
    if (!isPaymentHistoryIndex(value)) throw new TypeError(`${name} is not a valid payment history index`);
}

/**
 * Builds the index of a device that holds no payment.
 * @returns The empty index.
 */
export function emptyPaymentHistoryIndex(): PaymentHistoryIndex {
    return { version: PAYMENT_HISTORY_RECORD_VERSION, entries: [] };
}

/**
 * Places a record in the index by its creation time, moving it when that time changed.
 * @param index The index, `null` when never written.
 * @param entry The record's hash and creation time.
 * @returns The new index, or the one given when the record already sits where it belongs.
 */
export function placeInPaymentHistoryIndex(index: PaymentHistoryIndex | null, entry: PaymentHistoryIndexEntry): PaymentHistoryIndex | null {
    const current = index ?? emptyPaymentHistoryIndex();
    const placed = current.entries.find(({ paymentHash }) => paymentHash === entry.paymentHash);
    if (placed?.createdAtMs === entry.createdAtMs) return index;
    const entries = [...current.entries.filter(({ paymentHash }) => paymentHash !== entry.paymentHash), { ...entry }];
    return { ...current, entries: entries.sort(compareIndexEntries) };
}

/**
 * Builds a send's record as it leaves for the node, replacing a failed one under the same hash.
 * @param send The invoice and the budget.
 * @param nowMs The host's clock.
 * @returns The pending record.
 */
export function pendingSendRecord(send: PaymentHistorySend, nowMs: number): StoredPaymentRecord {
    return {
        version: PAYMENT_HISTORY_RECORD_VERSION,
        ...send,
        direction: "send",
        status: "pending",
        feeShannons: null,
        failedReason: null,
        createdAtMs: nowMs,
        settledAtMs: null,
    };
}

/**
 * Builds a receive's record as its payment arrives, keeping one already there.
 * @param current The record, `null` when the payment never arrived before.
 * @param receive The invoice.
 * @param nowMs The host's clock.
 * @returns The record.
 */
export function arrivedReceiveRecord(
    current: StoredPaymentRecord | null,
    receive: PaymentHistoryReceive,
    nowMs: number,
): StoredPaymentRecord {
    if (current !== null) return current;
    return {
        version: PAYMENT_HISTORY_RECORD_VERSION,
        ...receive,
        direction: "receive",
        status: "pending",
        maxFeeShannons: null,
        feeShannons: null,
        failedReason: null,
        createdAtMs: nowMs,
        settledAtMs: null,
    };
}

/**
 * Moves a record to how its payment ended; `completed` is final and only a send's `failed` turns `completed` (a false `Failed`).
 * @param current The record, `null` when there is none.
 * @param outcome How the payment ended.
 * @param nowMs The host's clock.
 * @returns The moved record, or the one given when the move is none.
 */
export function settlePaymentRecord(
    current: StoredPaymentRecord | null,
    outcome: PaymentHistoryOutcome,
    nowMs: number,
): StoredPaymentRecord | null {
    if (current === null || current.status === "completed" || current.status === outcome.status) return current;
    if (current.status === "failed" && current.direction === "receive") return current;
    if (outcome.status === "failed") return { ...current, status: "failed", failedReason: outcome.reason, settledAtMs: nowMs };
    return { ...current, status: "completed", feeShannons: outcome.feeShannons, failedReason: null, settledAtMs: nowMs };
}

/**
 * Strips a stored record down to what the host reads, as a copy.
 * @param stored The stored record.
 * @returns The record.
 */
export function toSdkPaymentRecord(stored: StoredPaymentRecord): SdkPaymentRecord {
    const { paymentHashHex, direction, status, amountShannons, invoice, description, maxFeeShannons, feeShannons } = stored;
    const { failedReason, createdAtMs, settledAtMs } = stored;
    return {
        paymentHashHex,
        direction,
        status,
        amountShannons,
        invoice,
        description,
        maxFeeShannons,
        feeShannons,
        failedReason,
        createdAtMs,
        settledAtMs,
    };
}

/**
 * Orders index entries newest first, ties by hash.
 * @param a An entry.
 * @param b Another entry.
 * @returns Negative when `a` goes first.
 */
function compareIndexEntries(a: PaymentHistoryIndexEntry, b: PaymentHistoryIndexEntry): number {
    if (a.createdAtMs !== b.createdAtMs) return b.createdAtMs - a.createdAtMs;
    return a.paymentHash < b.paymentHash ? -1 : 1;
}

/**
 * Checks one index entry.
 * @param value Value to check.
 * @returns Whether the value is an entry.
 */
function isIndexEntry(value: unknown): value is PaymentHistoryIndexEntry {
    return (
        isPlainObject(value) &&
        isHexBytes(value.paymentHash, PAYMENT_HASH_LENGTH) &&
        isUnsignedInteger(value.createdAtMs, Number.MAX_SAFE_INTEGER)
    );
}

/**
 * Checks that a value is one of a list of strings.
 * @param values The list.
 * @param value Value to check.
 * @returns Whether the value is in the list.
 */
function isOneOf<Values extends readonly string[]>(values: Values, value: unknown): value is Values[number] {
    return typeof value === "string" && values.includes(value);
}
