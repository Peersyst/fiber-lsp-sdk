import { HASH256_LENGTH, PAYMENT_HASH_LENGTH, isHexBytes, isPlainObject } from "../../common";
import { RPC_CHANNEL_STATE_NAMES, RPC_INVOICE_STATUSES, RPC_PAYMENT_STATUSES } from "../../rpc";
import { isWireHex } from "../../wire";
import { ACTIVITY_KINDS, ACTIVITY_RECORD_VERSION } from "../sdk.constants";
import type { ActivityKind, ActivityRecord, ActivityStatus } from "../sdk.types";

export type ActivityField = `${ActivityKind}s`;

const STATUSES: Record<ActivityKind, readonly string[]> = {
    channel: RPC_CHANNEL_STATE_NAMES,
    payment: RPC_PAYMENT_STATUSES,
    invoice: RPC_INVOICE_STATUSES,
};

/**
 * Names the record field that holds a kind's entries.
 * @param kind The kind.
 * @returns The field.
 */
export function activityField(kind: ActivityKind): ActivityField {
    return `${kind}s`;
}

/**
 * Checks that an id has the form the node reports a kind under: `0x` hex for a channel, bare hex for a payment hash.
 * @param kind The kind.
 * @param id Value to check.
 * @returns Whether the id fits the kind.
 */
export function isActivityId(kind: ActivityKind, id: unknown): id is string {
    return kind === "channel" ? isWireHex(id, HASH256_LENGTH) : isHexBytes(id, PAYMENT_HASH_LENGTH);
}

/**
 * Asserts that an id is one the node knows a kind by.
 * @param kind The kind.
 * @param id Value to check.
 */
export function assertActivityId(kind: ActivityKind, id: unknown): asserts id is string {
    if (!isActivityId(kind, id)) {
        const form =
            kind === "channel" ? `${HASH256_LENGTH} bytes of 0x-prefixed lowercase hex` : `${PAYMENT_HASH_LENGTH} bytes of lowercase hex`;
        throw new TypeError(`${kind} id must be ${form}`);
    }
}

/**
 * Checks that a value is a status the node reports for a kind.
 * @param kind The kind.
 * @param value Value to check.
 * @returns Whether the value is one of the kind's statuses.
 */
export function isActivityStatus<Kind extends ActivityKind>(kind: Kind, value: unknown): value is ActivityStatus<Kind> {
    return typeof value === "string" && STATUSES[kind].includes(value);
}

/**
 * Asserts that a value is a status the node reports for a kind.
 * @param kind The kind.
 * @param value Value to check.
 */
export function assertActivityStatus<Kind extends ActivityKind>(kind: Kind, value: unknown): asserts value is ActivityStatus<Kind> {
    if (!isActivityStatus(kind, value)) throw new TypeError(`${kind} status must be one of ${STATUSES[kind].join(", ")}`);
}

/**
 * Checks that a value has the exact shape of a stored {@link ActivityRecord}. Unknown extra fields are tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid activity record.
 */
export function isActivityRecord(value: unknown): value is ActivityRecord {
    if (!isPlainObject(value) || value.version !== ACTIVITY_RECORD_VERSION) return false;
    return ACTIVITY_KINDS.every((kind) => isActivityMap(kind, value[activityField(kind)]));
}

/**
 * Asserts that a value has the exact shape of a stored activity record.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertActivityRecord(name: string, value: unknown): asserts value is ActivityRecord {
    if (!isActivityRecord(value)) throw new TypeError(`${name} is not a valid activity record`);
}

/**
 * Builds the record of a device that watches nothing.
 * @returns The empty record.
 */
export function emptyActivityRecord(): ActivityRecord {
    return { version: ACTIVITY_RECORD_VERSION, channels: {}, payments: {}, invoices: {} };
}

/**
 * Checks one kind's entries: an object of ids the kind knows, each holding `null` or a status of the kind.
 * @param kind The kind.
 * @param value Value to check.
 * @returns Whether the value is a valid map of that kind's entries.
 */
function isActivityMap(kind: ActivityKind, value: unknown): boolean {
    if (!isPlainObject(value)) return false;
    return Object.entries(value).every(
        ([id, entry]) => isActivityId(kind, id) && isPlainObject(entry) && (entry.status === null || isActivityStatus(kind, entry.status)),
    );
}
