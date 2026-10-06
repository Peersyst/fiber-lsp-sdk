import type { ChannelPolicyRecord, DebitIntentRecord, HoldInvoicePolicyRecord } from "../policy.types";
import { isChannelPolicyRecord, isDebitIntentRecord, isHoldInvoicePolicyRecord } from "./validate.utils";

/**
 * Asserts that a value has the exact shape of a stored channel policy record.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertChannelPolicyRecord(name: string, value: unknown): asserts value is ChannelPolicyRecord {
    if (!isChannelPolicyRecord(value)) {
        throw new TypeError(`${name} is not a valid channel policy record`);
    }
}

/**
 * Asserts that a value has the exact shape of a stored debit intent record.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertDebitIntentRecord(name: string, value: unknown): asserts value is DebitIntentRecord {
    if (!isDebitIntentRecord(value)) {
        throw new TypeError(`${name} is not a valid debit intent record`);
    }
}

/**
 * Asserts that a value has the exact shape of a stored hold invoice record.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertHoldInvoicePolicyRecord(name: string, value: unknown): asserts value is HoldInvoicePolicyRecord {
    if (!isHoldInvoicePolicyRecord(value)) {
        throw new TypeError(`${name} is not a valid hold invoice record`);
    }
}
