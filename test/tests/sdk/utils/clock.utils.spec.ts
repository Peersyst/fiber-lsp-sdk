import { readSdkClock } from "../../../../src/sdk";

describe("readSdkClock", () => {
    it("reads the clock once, without a receiver", () => {
        const receivers: unknown[] = [];
        const now = jest.fn(function (this: unknown): number {
            receivers.push(this);
            return 1_791_367_260_000;
        });
        expect(readSdkClock(now)).toBe(1_791_367_260_000);
        expect(receivers).toEqual([undefined]);
    });

    it.each<[string, number]>([
        ["the epoch", 0],
        ["the largest safe integer", Number.MAX_SAFE_INTEGER],
    ])("takes a reading of %s", (_, reading) => {
        expect(readSdkClock(() => reading)).toBe(reading);
    });

    it.each<[string, unknown]>([
        ["a fractional reading", 1.5],
        ["a negative reading", -1],
        ["a reading past the largest safe integer", 9_007_199_254_740_992],
        ["a reading of NaN", Number.NaN],
        ["a reading in a string", "1791367260000"],
        ["a reading in a bigint", 1_791_367_260_000n],
    ])("refuses %s", (_, reading) => {
        expect(() => readSdkClock(() => reading as number)).toThrow(
            new RangeError(`now() must be an integer between 0 and 9007199254740991, got ${String(reading)}`),
        );
    });
});
