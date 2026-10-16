import { SignerStore } from "../../../src/policy";
import type { ActivityRecord } from "../../../src/sdk";
import { ACTIVITY_RECORD_KEY, ActivityTracker } from "../../../src/sdk";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";

const KEY = "fiber-lsp-sdk:activity";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_CHANNEL_ID = `0x${"2e".repeat(32)}`;
const HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);
const EMPTY: ActivityRecord = { version: 1, channels: {}, payments: {}, invoices: {} };

function harness(storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage()) {
    return { tracker: new ActivityTracker(new SignerStore(storage)), storage };
}

describe("ActivityTracker", () => {
    it("pins the key", () => {
        expect(ACTIVITY_RECORD_KEY).toBe(KEY);
    });

    describe("read", () => {
        it("reads an empty record when nothing was ever watched, writing nothing", async () => {
            const h = harness();
            await expect(h.tracker.read()).resolves.toEqual(EMPTY);
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
        });

        it("reads what a previous instance wrote", async () => {
            const storage = new InMemorySignerStorage();
            await harness(storage).tracker.watch("channel", CHANNEL_ID);
            await expect(harness(storage).tracker.read()).resolves.toEqual({ ...EMPTY, channels: { [CHANNEL_ID]: { status: null } } });
        });

        it("reads through an asynchronous storage", async () => {
            const h = harness(new AsyncInMemorySignerStorage());
            await h.tracker.watch("payment", HASH);
            await expect(h.tracker.read()).resolves.toEqual({ ...EMPTY, payments: { [HASH]: { status: null } } });
        });
    });

    describe("watch", () => {
        it("adds an entry with no status, under the kind's field, and persists the record as JSON", async () => {
            const h = harness();
            await h.tracker.watch("channel", CHANNEL_ID);
            await h.tracker.watch("payment", HASH);
            await h.tracker.watch("invoice", OTHER_HASH);
            expect(h.storage.map.get(KEY)).toBe(
                `{"version":1,"channels":{"${CHANNEL_ID}":{"status":null}},"payments":{"${HASH}":{"status":null}},"invoices":{"${OTHER_HASH}":{"status":null}}}`,
            );
            expect([...h.storage.map.keys()]).toEqual([KEY]);
        });

        it("keeps the entry, status included, when something is watched again", async () => {
            const h = harness();
            await h.tracker.watch("payment", HASH);
            await h.tracker.mark("payment", HASH, "Inflight");
            h.storage.ops.length = 0;
            await h.tracker.watch("payment", HASH);
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
            await expect(h.tracker.read()).resolves.toEqual({ ...EMPTY, payments: { [HASH]: { status: "Inflight" } } });
        });

        it("keeps the kinds apart for one id", async () => {
            const h = harness();
            await h.tracker.watch("payment", HASH);
            await h.tracker.watch("invoice", HASH);
            await expect(h.tracker.read()).resolves.toEqual({
                ...EMPTY,
                payments: { [HASH]: { status: null } },
                invoices: { [HASH]: { status: null } },
            });
        });

        it("keeps the other entries of the kind", async () => {
            const h = harness();
            await h.tracker.watch("channel", CHANNEL_ID);
            await h.tracker.mark("channel", CHANNEL_ID, "ChannelReady");
            await h.tracker.watch("channel", OTHER_CHANNEL_ID);
            await expect(h.tracker.read()).resolves.toEqual({
                ...EMPTY,
                channels: { [CHANNEL_ID]: { status: "ChannelReady" }, [OTHER_CHANNEL_ID]: { status: null } },
            });
        });

        it.each([
            ["channel", "", "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", CHANNEL_ID.slice(2), "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["payment", `0x${HASH}`, "payment id must be 32 bytes of lowercase hex"],
            ["invoice", HASH.toUpperCase(), "invoice id must be 32 bytes of lowercase hex"],
        ] as const)("refuses, as a %s id, %p before touching the storage", async (kind, id, message) => {
            const h = harness();
            await expect(h.tracker.watch(kind, id)).rejects.toThrow(new TypeError(message));
            expect(h.storage.ops).toEqual([]);
        });
    });

    describe("mark", () => {
        it("records the status an event was emitted for", async () => {
            const h = harness();
            await h.tracker.watch("invoice", HASH);
            await h.tracker.mark("invoice", HASH, "Received");
            await expect(h.tracker.read()).resolves.toEqual({ ...EMPTY, invoices: { [HASH]: { status: "Received" } } });
            await h.tracker.mark("invoice", HASH, "Paid");
            await expect(h.tracker.read()).resolves.toEqual({ ...EMPTY, invoices: { [HASH]: { status: "Paid" } } });
        });

        it("keeps an entry's unknown fields, which a later version may have added", async () => {
            const h = harness();
            h.storage.map.set(KEY, `{"version":1,"channels":{},"payments":{"${HASH}":{"status":null,"extra":true}},"invoices":{}}`);
            await h.tracker.mark("payment", HASH, "Inflight");
            expect(h.storage.map.get(KEY)).toBe(
                `{"version":1,"channels":{},"payments":{"${HASH}":{"status":"Inflight","extra":true}},"invoices":{}}`,
            );
        });

        it("writes nothing when the status is the one recorded", async () => {
            const h = harness();
            await h.tracker.watch("channel", CHANNEL_ID);
            await h.tracker.mark("channel", CHANNEL_ID, "ChannelReady");
            h.storage.ops.length = 0;
            await h.tracker.mark("channel", CHANNEL_ID, "ChannelReady");
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
        });

        it("refuses to mark something that is not watched, writing nothing", async () => {
            const h = harness();
            await h.tracker.watch("payment", OTHER_HASH);
            h.storage.ops.length = 0;
            await expect(h.tracker.mark("payment", HASH, "Success")).rejects.toThrow(new TypeError(`payment ${HASH} is not being watched`));
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
        });

        it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
            "refuses a channel named %s, which the node never names one, before touching the storage",
            async (id) => {
                const h = harness();
                const error = new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex");
                await expect(h.tracker.watch("channel", id)).rejects.toThrow(error);
                await expect(h.tracker.mark("channel", id, "ChannelReady")).rejects.toThrow(error);
                await expect(h.tracker.forget("channel", id)).rejects.toThrow(error);
                expect(h.storage.ops).toEqual([]);
            },
        );

        it("refuses to mark something watched under another kind", async () => {
            const h = harness();
            await h.tracker.watch("payment", HASH);
            await expect(h.tracker.mark("invoice", HASH, "Paid")).rejects.toThrow(new TypeError(`invoice ${HASH} is not being watched`));
        });

        it.each([
            ["channel", CHANNEL_ID, "Paid", "channel status must be one of"],
            ["payment", HASH, "ChannelReady", "payment status must be one of Created, Inflight, Success, Failed"],
            ["invoice", HASH, "Success", "invoice status must be one of Open, Cancelled, Expired, Received, Paid"],
            ["invoice", HASH, null, "invoice status must be one of Open, Cancelled, Expired, Received, Paid"],
        ] as const)("refuses, for a %s, the status %p before touching the storage", async (kind, id, status, message) => {
            const h = harness();
            await h.tracker.watch(kind, id);
            h.storage.ops.length = 0;
            await expect(h.tracker.mark(kind, id, status as never)).rejects.toThrow(TypeError);
            await expect(h.tracker.mark(kind, id, status as never)).rejects.toThrow(message);
            expect(h.storage.ops).toEqual([]);
        });

        it("refuses a malformed id before touching the storage", async () => {
            const h = harness();
            await expect(h.tracker.mark("payment", "nope", "Success")).rejects.toThrow(
                new TypeError("payment id must be 32 bytes of lowercase hex"),
            );
            expect(h.storage.ops).toEqual([]);
        });
    });

    describe("forget", () => {
        it("removes the entry and keeps the others", async () => {
            const h = harness();
            await h.tracker.watch("payment", HASH);
            await h.tracker.watch("payment", OTHER_HASH);
            await h.tracker.mark("payment", OTHER_HASH, "Inflight");
            await h.tracker.forget("payment", HASH);
            await expect(h.tracker.read()).resolves.toEqual({ ...EMPTY, payments: { [OTHER_HASH]: { status: "Inflight" } } });
            expect(h.storage.map.get(KEY)).toBe(
                `{"version":1,"channels":{},"payments":{"${OTHER_HASH}":{"status":"Inflight"}},"invoices":{}}`,
            );
        });

        it("writes nothing when the entry is not there", async () => {
            const h = harness();
            await h.tracker.watch("invoice", HASH);
            h.storage.ops.length = 0;
            await h.tracker.forget("invoice", OTHER_HASH);
            await h.tracker.forget("payment", HASH);
            expect(h.storage.ops).toEqual([`get ${KEY}`, `get ${KEY}`]);
        });

        it("writes nothing when nothing was ever watched", async () => {
            const h = harness();
            await h.tracker.forget("channel", CHANNEL_ID);
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
            expect(h.storage.map.size).toBe(0);
        });

        it("is idempotent", async () => {
            const h = harness();
            await h.tracker.watch("channel", CHANNEL_ID);
            await h.tracker.forget("channel", CHANNEL_ID);
            await h.tracker.forget("channel", CHANNEL_ID);
            await expect(h.tracker.read()).resolves.toEqual(EMPTY);
        });

        it("refuses a malformed id before touching the storage", async () => {
            const h = harness();
            await expect(h.tracker.forget("channel", "")).rejects.toThrow(
                new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex"),
            );
            expect(h.storage.ops).toEqual([]);
        });
    });

    describe("the stored record", () => {
        it.each([
            ["not JSON", "{activity"],
            ["a version from the future", '{"version":2,"channels":{},"payments":{},"invoices":{}}'],
            ["missing a kind", '{"version":1,"channels":{},"payments":{}}'],
            ["a kind that is an array", '{"version":1,"channels":[],"payments":{},"invoices":{}}'],
            ["a status of another kind", `{"version":1,"channels":{"${CHANNEL_ID}":{"status":"Paid"}},"payments":{},"invoices":{}}`],
            ["an entry without a status", `{"version":1,"channels":{},"payments":{"${HASH}":{}},"invoices":{}}`],
            ["empty", ""],
        ])("throws on a stored record that is %s instead of reading it as empty", async (_, raw) => {
            const h = harness();
            h.storage.map.set(KEY, raw);
            await expect(h.tracker.read()).rejects.toThrow(
                new TypeError(`stored value at ${KEY} is not ${raw === "" || raw === "{activity" ? "valid JSON" : "a activity record"}`),
            );
            await expect(h.tracker.watch("channel", CHANNEL_ID)).rejects.toThrow(TypeError);
            await expect(h.tracker.forget("channel", CHANNEL_ID)).rejects.toThrow(TypeError);
            expect(h.storage.map.get(KEY)).toBe(raw);
        });

        it("tolerates unknown extra fields and keeps them", async () => {
            const h = harness();
            h.storage.map.set(KEY, `{"version":1,"channels":{},"payments":{},"invoices":{},"extra":true}`);
            await h.tracker.watch("payment", HASH);
            expect(h.storage.map.get(KEY)).toBe(
                `{"version":1,"channels":{},"payments":{"${HASH}":{"status":null}},"invoices":{},"extra":true}`,
            );
        });

        it("propagates a storage failure", async () => {
            const h = harness();
            h.storage.set = () => {
                throw new Error("disk full");
            };
            await expect(h.tracker.watch("payment", HASH)).rejects.toThrow(new Error("disk full"));
        });
    });

    describe("concurrency", () => {
        it("loses nothing to concurrent updates under an asynchronous storage", async () => {
            const h = harness(new AsyncInMemorySignerStorage());
            await Promise.all([
                h.tracker.watch("channel", CHANNEL_ID),
                h.tracker.watch("payment", HASH),
                h.tracker.watch("invoice", OTHER_HASH),
                h.tracker.watch("channel", OTHER_CHANNEL_ID),
            ]);
            await Promise.all([h.tracker.mark("payment", HASH, "Inflight"), h.tracker.forget("channel", CHANNEL_ID)]);
            await expect(h.tracker.read()).resolves.toEqual({
                version: 1,
                channels: { [OTHER_CHANNEL_ID]: { status: null } },
                payments: { [HASH]: { status: "Inflight" } },
                invoices: { [OTHER_HASH]: { status: null } },
            });
        });
    });
});
