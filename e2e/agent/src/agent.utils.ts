import { AgentRequestError } from "./agent.error";

/**
 * Reads a JSON object, refusing anything else.
 * @param value The value read.
 * @param field Where it sits, for the refusal.
 * @returns The object.
 */
export function readJsonObject(value: unknown, field: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new AgentRequestError(`${field} must be an object`);
    return value as Record<string, unknown>;
}

/**
 * Reads an error's message, whatever was thrown.
 * @param error What was thrown.
 * @returns Its message.
 */
export function messageOf(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

/**
 * Writes hex without its `0x`, lowercase.
 * @param hex The hex, with or without `0x`.
 * @returns The bare lowercase hex.
 */
export function bareLowerHex(hex: string): string {
    return (hex.startsWith("0x") ? hex.slice(2) : hex).toLowerCase();
}
