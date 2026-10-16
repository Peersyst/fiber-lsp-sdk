import { MAX_CHANNEL_INDEX } from "../../../src/derivation";
import { SignerStore } from "../../../src/policy";
import { ALLOCATION_FLOOR_MS, ALLOCATOR_KEY_PREFIX, IndexAllocator, SdkError } from "../../../src/sdk";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import { rejection } from "../../utils/rejection";

// 2026-10-07T10:00:00.250Z
const NOW_MS = 1_791_367_200_250;
const NOW_S = 1_791_367_200;
const CHANNEL_KEY = "fiber-lsp-sdk:allocator:channel";
const INVOICE_KEY = "fiber-lsp-sdk:allocator:invoice";

function harness(
    now: () => number = () => NOW_MS,
    storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage(),
) {
    const allocator = new IndexAllocator(new SignerStore(storage), now);
    return { allocator, storage };
}

describe("IndexAllocator", () => {
    it("pins the floor and the key prefix", () => {
        expect(ALLOCATION_FLOOR_MS).toBe(1_790_812_800_000);
        expect(new Date(ALLOCATION_FLOOR_MS).toISOString()).toBe("2026-10-01T00:00:00.000Z");
        expect(ALLOCATOR_KEY_PREFIX).toBe("fiber-lsp-sdk:allocator:");
    });

    describe("channel indexes", () => {
        it("hands out the clock in whole seconds the first time", async () => {
            const h = harness();
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S);
        });

        it("rounds a reading late in its second down, never up", async () => {
            const h = harness(() => NOW_S * 1_000 + 999);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S);
        });

        it("persists the index as the last one, as a JSON integer under its key, before resolving", async () => {
            const h = harness();
            const pending = h.allocator.allocateChannelIndex();
            await pending;
            expect(h.storage.ops).toEqual([`get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`]);
            expect(h.storage.map.get(CHANNEL_KEY)).toBe(String(NOW_S));
        });

        it("writes before it resolves, with an asynchronous storage too", async () => {
            const storage = new AsyncInMemorySignerStorage();
            const h = harness(() => NOW_MS, storage);
            await h.allocator.allocateChannelIndex();
            expect(storage.map.get(CHANNEL_KEY)).toBe(String(NOW_S));
        });

        it("hands out one past the last index while the clock stays within the same second", async () => {
            const h = harness();
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 1);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 2);
            expect(h.storage.map.get(CHANNEL_KEY)).toBe(String(NOW_S + 2));
        });

        it("hands out one past the last index when the clock goes back", async () => {
            let now = NOW_MS;
            const h = harness(() => now);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S);
            now = NOW_MS - 3_600_000;
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 1);
        });

        it("follows the clock once it has moved past the last index", async () => {
            let now = NOW_MS;
            const h = harness(() => now);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 1);
            now = NOW_MS + 2_000;
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 2);
            now = NOW_MS + 60_000;
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 60);
        });

        it("takes the clock exactly at the floor, and one past a last index at the floor", async () => {
            const h = harness(() => ALLOCATION_FLOOR_MS);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(ALLOCATION_FLOOR_MS / 1000);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(ALLOCATION_FLOOR_MS / 1000 + 1);
        });

        it("picks up the last index a previous instance persisted", async () => {
            const storage = new InMemorySignerStorage();
            await harness(() => NOW_MS, storage).allocator.allocateChannelIndex();
            await expect(harness(() => NOW_MS, storage).allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 1);
        });
    });

    describe("invoice indexes", () => {
        it("hands out the clock in milliseconds the first time, under its own key", async () => {
            const h = harness();
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS);
            expect(h.storage.ops).toEqual([`get ${INVOICE_KEY}`, `set ${INVOICE_KEY}`]);
            expect(h.storage.map.get(INVOICE_KEY)).toBe(String(NOW_MS));
        });

        it("hands out one past the last index while the clock stands still or goes back", async () => {
            let now = NOW_MS;
            const h = harness(() => now);
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS);
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS + 1);
            now = NOW_MS - 1;
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS + 2);
            now = NOW_MS + 3;
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS + 3);
        });

        it("keeps the two sequences apart", async () => {
            const h = harness();
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S);
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS);
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(NOW_S + 1);
            await expect(h.allocator.allocateInvoiceIndex()).resolves.toBe(NOW_MS + 1);
            expect([...h.storage.map.keys()].sort()).toEqual([CHANNEL_KEY, INVOICE_KEY]);
        });
    });

    describe("the clock", () => {
        it.each([
            ["one millisecond before the floor", ALLOCATION_FLOOR_MS - 1],
            ["the epoch", 0],
            ["a clock restarted at 2000", Date.UTC(2000, 0, 1)],
        ])("refuses %s as clock_before_floor, writing nothing", async (_, now) => {
            const h = harness(() => now);
            for (const allocate of [() => h.allocator.allocateChannelIndex(), () => h.allocator.allocateInvoiceIndex()]) {
                const error = await rejection(allocate());
                expect(error).toBeInstanceOf(SdkError);
                expect((error as SdkError).code).toBe("clock_before_floor");
                expect((error as SdkError).message).toBe(`the clock reads ${now}, before the allocation floor ${ALLOCATION_FLOOR_MS}`);
            }
            expect(h.storage.ops).toEqual([]);
        });

        it.each([
            NaN,
            Infinity,
            -1,
            1.5,
            NOW_MS + 0.5,
            Number.MAX_SAFE_INTEGER + 2,
            "1791367200250" as unknown as number,
            undefined as unknown as number,
        ])("refuses a clock reading of %p as the host's error, writing nothing", async (now) => {
            const h = harness(() => now);
            await expect(h.allocator.allocateChannelIndex()).rejects.toThrow(
                new TypeError(`now() must return whole milliseconds since the epoch, got ${now}`),
            );
            await expect(h.allocator.allocateInvoiceIndex()).rejects.toThrow(TypeError);
            expect(h.storage.ops).toEqual([]);
        });

        it("reads the clock on every allocation", async () => {
            const readings: number[] = [];
            const h = harness(() => {
                readings.push(NOW_MS);
                return NOW_MS;
            });
            await h.allocator.allocateChannelIndex();
            await h.allocator.allocateInvoiceIndex();
            expect(readings).toHaveLength(2);
        });
    });

    describe("the stored last index", () => {
        it.each([
            ["not JSON", "last"],
            ["a string", '"1791367200"'],
            ["negative", "-1"],
            ["fractional", "1791367200.5"],
            ["above the channel index bound", String(MAX_CHANNEL_INDEX + 2)],
            ["an object", '{"last":1791367200}'],
            ["null", "null"],
            ["empty", ""],
        ])("throws on a stored value that is %s instead of starting over from the clock", async (_, raw) => {
            const h = harness();
            h.storage.map.set(CHANNEL_KEY, raw);
            await expect(h.allocator.allocateChannelIndex()).rejects.toThrow(TypeError);
            expect(h.storage.map.get(CHANNEL_KEY)).toBe(raw);
        });

        it("takes a last index at the channel index bound as the last one it can hand out", async () => {
            const h = harness();
            h.storage.map.set(CHANNEL_KEY, String(MAX_CHANNEL_INDEX - 1));
            await expect(h.allocator.allocateChannelIndex()).resolves.toBe(MAX_CHANNEL_INDEX);
            await expect(h.allocator.allocateChannelIndex()).rejects.toThrow(
                new TypeError("updated record is not a valid last allocated index"),
            );
            expect(h.storage.map.get(CHANNEL_KEY)).toBe(String(MAX_CHANNEL_INDEX));
        });

        it("propagates a storage failure", async () => {
            const h = harness();
            h.storage.get = () => {
                throw new Error("disk gone");
            };
            await expect(h.allocator.allocateChannelIndex()).rejects.toThrow(new Error("disk gone"));
        });
    });

    describe("concurrency", () => {
        it("hands out distinct indexes to concurrent allocations under an asynchronous storage", async () => {
            const h = harness(() => NOW_MS, new AsyncInMemorySignerStorage());
            const indexes = await Promise.all([
                h.allocator.allocateChannelIndex(),
                h.allocator.allocateChannelIndex(),
                h.allocator.allocateChannelIndex(),
            ]);
            expect(indexes).toEqual([NOW_S, NOW_S + 1, NOW_S + 2]);
            expect(h.storage.map.get(CHANNEL_KEY)).toBe(String(NOW_S + 2));
        });

        it("does not serialize the two kinds against each other", async () => {
            const storage = new AsyncInMemorySignerStorage();
            const h = harness(() => NOW_MS, storage);
            await Promise.all([h.allocator.allocateChannelIndex(), h.allocator.allocateInvoiceIndex()]);
            expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`, `get ${INVOICE_KEY}`, `set ${CHANNEL_KEY}`, `set ${INVOICE_KEY}`]);
        });
    });
});
