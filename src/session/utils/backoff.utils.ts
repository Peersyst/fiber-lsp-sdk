import type { ReconnectPolicy } from "../session.types";

/**
 * Computes the delay before a reconnect attempt: exponential from the initial delay, capped, with full jitter.
 * @param policy The reconnect policy.
 * @param attempt Failed attempts since the last established session, so `0` for the first retry.
 * @param random Uniform in `[0, 1)`.
 * @returns The delay in whole milliseconds.
 */
export function backoffDelayMs(policy: ReconnectPolicy, attempt: number, random: () => number): number {
    const base = Math.min(policy.maxDelayMs, policy.initialDelayMs * policy.factor ** attempt);
    return Math.floor(base * random());
}
