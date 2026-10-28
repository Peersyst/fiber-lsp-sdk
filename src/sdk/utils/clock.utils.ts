import { assertUnsignedInteger } from "../../common";

/**
 * Reads the host's clock once, unbound so it gets no receiver, refusing a reading that is no count of milliseconds.
 * @param now The host's clock.
 * @returns Milliseconds since the epoch.
 */
export function readSdkClock(now: () => number): number {
    const nowMs = now();
    assertUnsignedInteger("now()", nowMs, Number.MAX_SAFE_INTEGER);
    return nowMs;
}
