import type { ReconnectPolicy } from "../../../../src/session";
import { DEFAULT_RECONNECT_POLICY, sessionBackoffDelayMs } from "../../../../src/session";

const POLICY: ReconnectPolicy = { initialDelayMs: 1000, factor: 2, maxDelayMs: 30_000 };

describe("sessionBackoffDelayMs", () => {
    it("is pinned to the defaults it will run with", () => {
        expect(DEFAULT_RECONNECT_POLICY).toEqual(POLICY);
    });

    it.each([
        [0, 1000],
        [1, 2000],
        [2, 4000],
        [3, 8000],
        [4, 16_000],
        [5, 30_000],
        [6, 30_000],
        [100, 30_000],
    ])("doubles from the initial delay and stops at the cap: attempt %i waits %i ms without jitter", (attempt, delay) => {
        expect(sessionBackoffDelayMs(POLICY, attempt, () => 1)).toBe(delay);
    });

    it("scales the whole delay by the random draw, so the jitter spans from zero", () => {
        expect(sessionBackoffDelayMs(POLICY, 2, () => 0.5)).toBe(2000);
        expect(sessionBackoffDelayMs(POLICY, 2, () => 0)).toBe(0);
        expect(sessionBackoffDelayMs(POLICY, 10, () => 0.25)).toBe(7500);
    });

    it("rounds down to whole milliseconds", () => {
        expect(sessionBackoffDelayMs(POLICY, 0, () => 0.9999)).toBe(999);
    });

    it("draws once per call", () => {
        const draws: number[] = [];
        sessionBackoffDelayMs(POLICY, 0, () => {
            draws.push(1);
            return 1;
        });
        expect(draws).toHaveLength(1);
    });

    it("stays flat under a factor of 1", () => {
        expect(sessionBackoffDelayMs({ ...POLICY, factor: 1 }, 7, () => 1)).toBe(1000);
    });

    it("honours a cap below the initial delay", () => {
        expect(sessionBackoffDelayMs({ initialDelayMs: 1000, factor: 2, maxDelayMs: 500 }, 0, () => 1)).toBe(500);
    });

    it("survives an attempt count whose power overflows", () => {
        expect(sessionBackoffDelayMs(POLICY, 5000, () => 1)).toBe(30_000);
    });
});
