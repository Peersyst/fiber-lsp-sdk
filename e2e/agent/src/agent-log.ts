import { bytesToHex } from "@noble/hashes/utils.js";

export type AgentLogger = (kind: string, fields: Readonly<Record<string, unknown>>) => void;

/**
 * Writes an error as the fields a log reader needs: its name, its message, its code when it has one, and its cause.
 * @param error The error.
 * @returns The fields, the cause written the same way by the replacer.
 */
function errorFields(error: Error): Record<string, unknown> {
    const fields: Record<string, unknown> = { name: error.name, message: error.message };
    if ("code" in error) fields.code = error.code;
    if (error.cause !== undefined) fields.cause = error.cause;
    return fields;
}

/**
 * Writes what JSON cannot: a `bigint` as its decimal string, bytes as lowercase hex and an error as its fields.
 * @param _key The key, unused.
 * @param value The value.
 * @returns The value JSON writes.
 */
function logValue(_key: string, value: unknown): unknown {
    if (typeof value === "bigint") return value.toString();
    if (value instanceof Uint8Array) return bytesToHex(value);
    if (value instanceof Error) return errorFields(value);
    return value;
}

/**
 * Writes one line of the agent's log: a JSON object with the time, what happened, and its fields.
 * @param nowMs The time, in milliseconds since the epoch.
 * @param kind What happened.
 * @param fields Its details.
 * @returns The line, without its newline.
 */
export function agentLogLine(nowMs: number, kind: string, fields: Readonly<Record<string, unknown>>): string {
    return JSON.stringify({ ts: new Date(nowMs).toISOString(), kind, ...fields }, logValue);
}

/**
 * Builds the logger that writes each entry as one line.
 * @param now The clock the lines are stamped with.
 * @param write Where a line goes, without its newline.
 * @returns The logger.
 */
export function agentLogger(now: () => number, write: (line: string) => void): AgentLogger {
    return (kind, fields) => write(agentLogLine(now(), kind, fields));
}
