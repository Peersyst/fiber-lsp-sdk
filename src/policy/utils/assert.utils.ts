import { isChannelPolicyRecord } from "./validate.utils";

/**
 * Asserts that a value has the exact shape of a stored channel policy record.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertChannelPolicyRecord(name: string, value: unknown): void {
    if (!isChannelPolicyRecord(value)) {
        throw new TypeError(`${name} is not a valid channel policy record`);
    }
}
