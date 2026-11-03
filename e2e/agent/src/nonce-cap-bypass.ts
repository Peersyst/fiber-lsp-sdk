import type { ISignerStorage } from "@peersyst/fiber-lsp-sdk";
import { HASH256_HEX_LENGTH } from "./agent.constants";
import { isBareHex } from "./agent.utils";

// The SDK's channel policy record, as `src/policy` keys it; the alias keys sit under another prefix.
const CHANNEL_RECORD_KEY_PREFIX = "fiber-lsp-sdk:channel:";

/**
 * Checks that a value is a JSON object, not an array.
 * @param value The parsed value.
 * @returns Whether it is one.
 */
function isJsonObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Checks that a mark is one the SDK reads: a second session on a signed slot.
 * @param mark The slot's `nonceReuse` entry.
 * @param first The slot's signed session.
 * @returns Whether the mark is well formed.
 */
function isServedMark(mark: unknown, first: unknown): mark is { sessionCommitment: string } {
    return (
        isJsonObject(mark) &&
        isBareHex(mark.sessionCommitment, HASH256_HEX_LENGTH) &&
        isBareHex(mark.message, HASH256_HEX_LENGTH) &&
        typeof first === "string" &&
        first !== mark.sessionCommitment
    );
}

/**
 * Promotes a channel record's `nonceReuse` marks to its slots' signed sessions, leaving anything else as stored.
 * @param raw The stored value.
 * @returns The value the SDK reads.
 */
function servingLatestSession(raw: string): string {
    let record: unknown;
    try {
        record = JSON.parse(raw);
    } catch {
        return raw;
    }
    if (!isJsonObject(record)) return raw;
    const { nonceReuse, signedSessions } = record;
    if (!isJsonObject(nonceReuse) || !isJsonObject(signedSessions) || Object.keys(nonceReuse).length === 0) return raw;
    const latest: Record<string, unknown> = { ...signedSessions };
    for (const [slot, mark] of Object.entries(nonceReuse)) {
        // A mark the SDK would not read (a slot no session signed, its first session again, another shape) is the SDK's to refuse.
        if (!isServedMark(mark, signedSessions[slot])) return raw;
        latest[slot] = mark.sessionCommitment;
    }
    return JSON.stringify({ ...record, signedSessions: latest, nonceReuse: {} });
}

/**
 * Test-only: serves the third session on a slot Fiber's nonce lifecycle asks for, which `nonceReuse: "allow"` refuses since
 * three signatures under one deterministic nonce solve for the funding key. Goes once Fiber's nonces are strict.
 */
export class NonceCapBypassStorage implements ISignerStorage {
    /**
     * Wraps the storage the SDK would read.
     * @param inner The agent's storage.
     */
    constructor(private readonly inner: ISignerStorage) {}

    /**
     * Reads a stored value, a channel record with each slot's latest session as its signed one.
     * @param key Key to read.
     * @returns The stored value, or `null` if the key was never written.
     */
    get(key: string): string | null {
        const raw = this.inner.get(key);
        return raw === null || !key.startsWith(CHANNEL_RECORD_KEY_PREFIX) ? raw : servingLatestSession(raw);
    }

    /**
     * Writes a value through.
     * @param key Key to write.
     * @param value Value to store.
     */
    set(key: string, value: string): void {
        this.inner.set(key, value);
    }
}
