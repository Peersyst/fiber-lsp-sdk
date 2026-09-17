import { HASH256_LENGTH } from "../../common";
import type { Field } from "../../wire";
import { malformed, requireHexBytes } from "../../wire";
import { MAX_REQUEST_ID_LENGTH } from "../protocol.constants";

// Printable ASCII, so that a character and a byte count the same on both ends of the wire.
const REQUEST_ID_PATTERN = /^[\x20-\x7e]*$/;

const REQUEST_ID_FORM = `a string of 1 to ${MAX_REQUEST_ID_LENGTH} printable ASCII characters`;

/**
 * Checks that a value is a request id: one to `MAX_REQUEST_ID_LENGTH` printable ASCII characters, otherwise opaque.
 * @param value Value to check.
 * @returns Whether the value is a request id.
 */
export function isRequestId(value: unknown): value is string {
    return typeof value === "string" && value.length > 0 && value.length <= MAX_REQUEST_ID_LENGTH && REQUEST_ID_PATTERN.test(value);
}

/**
 * Asserts that a request id the device is about to write is one the wire accepts.
 * @param requestId Id to check.
 */
export function assertRequestId(requestId: string): void {
    if (!isRequestId(requestId)) throw new TypeError(`requestId must be ${REQUEST_ID_FORM}`);
}

/**
 * Reads a field as a request id.
 * @param field Field to read.
 * @returns The id, echoed verbatim in the answer.
 */
export function decodeRequestId(field: Field): string {
    if (!isRequestId(field.value)) malformed(field, `must be ${REQUEST_ID_FORM}`);
    return field.value;
}

/**
 * Reads a field as a channel id, fiber's `Hash256`, keeping the wire string the policy record is aliased by.
 * @param field Field to read.
 * @returns The id in wire form.
 */
export function decodeChannelId(field: Field): string {
    return requireHexBytes(field, HASH256_LENGTH);
}
