import { setTimeout as delay } from "node:timers/promises";

// An opening waits on the funding tx's confirmation and fiber's channel-ready exchange: minutes on a loaded devnet.
export const OPENING_TIMEOUT_MS = 5 * 60_000;

export const EVENT_TIMEOUT_MS = 2 * 60_000;

// Gossip runs every second on the devnet, but an announcement waits on the funding tx's confirmations first.
export const GRAPH_TIMEOUT_MS = 3 * 60_000;

export const PROBE_INTERVAL_MS = 1000;

export function sleep(ms: number): Promise<void> {
    return delay(ms);
}

export type WaitOptions = { timeoutMs: number; intervalMs?: number };

export class WaitTimeoutError extends Error {}

export async function waitUntil<T>(what: string, probe: () => Promise<T | undefined>, options: WaitOptions): Promise<T> {
    const deadline = Date.now() + options.timeoutMs;
    for (;;) {
        const value = await probe();
        if (value !== undefined) return value;
        if (Date.now() >= deadline) throw new WaitTimeoutError(`timed out after ${options.timeoutMs} ms waiting for ${what}`);
        await sleep(options.intervalMs ?? PROBE_INTERVAL_MS);
    }
}
