import { SignerStore } from "../../../src/policy";
import type { StoredPaymentRecord } from "../../../src/sdk";
import { PAYMENT_HISTORY_INDEX_KEY, PAYMENT_HISTORY_RECORD_KEY_PREFIX, PaymentHistory } from "../../../src/sdk";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";

const INDEX_KEY = "fiber-lsp-sdk:payment-history";
const HASH_A = "aa".repeat(32);
const HASH_B = "bb".repeat(32);
const HASH_C = "cc".repeat(32);
const KEY_A = `fiber-lsp-sdk:payment-history:${HASH_A}`;
const KEY_B = `fiber-lsp-sdk:payment-history:${HASH_B}`;
const KEY_C = `fiber-lsp-sdk:payment-history:${HASH_C}`;
const INVOICE = "fibt1000000001pcsaug0p0exgfw0pnm6vk0rnt4xefskmrz0g";

const SEND_A: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_A}`,
    direction: "send",
    status: "pending",
    amountShannons: "100000",
    invoice: INVOICE,
    description: "coffee",
    maxFeeShannons: "500",
    feeShannons: null,
    failedReason: null,
    createdAtMs: 1000,
    settledAtMs: null,
};

const COMPLETED_A: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_A}`,
    direction: "send",
    status: "completed",
    amountShannons: "100000",
    invoice: INVOICE,
    description: "coffee",
    maxFeeShannons: "500",
    feeShannons: "7",
    failedReason: null,
    createdAtMs: 1000,
    settledAtMs: 1500,
};

const RECEIVE_B: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_B}`,
    direction: "receive",
    status: "pending",
    amountShannons: "200000",
    invoice: INVOICE,
    description: null,
    maxFeeShannons: null,
    feeShannons: null,
    failedReason: null,
    createdAtMs: 3000,
    settledAtMs: null,
};

const SEND_C: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_C}`,
    direction: "send",
    status: "failed",
    amountShannons: "300000",
    invoice: INVOICE,
    description: "rent",
    maxFeeShannons: "0",
    feeShannons: null,
    failedReason: "no path found",
    createdAtMs: 2000,
    settledAtMs: 2500,
};

function harness(storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage()) {
    return { history: new PaymentHistory(new SignerStore(storage)), storage };
}

async function seeded(storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage()) {
    const h = harness(storage);
    await h.history.update(HASH_A, () => SEND_A);
    await h.history.update(HASH_B, () => RECEIVE_B);
    await h.history.update(HASH_C, () => SEND_C);
    h.storage.ops.length = 0;
    return h;
}

describe("PaymentHistory", () => {
    it("pins the keys", () => {
        expect(PAYMENT_HISTORY_INDEX_KEY).toBe(INDEX_KEY);
        expect(PAYMENT_HISTORY_RECORD_KEY_PREFIX).toBe(`${INDEX_KEY}:`);
    });

    describe("read", () => {
        it("reads null when the history holds no record of the hash, writing nothing", async () => {
            const h = harness();
            await expect(h.history.read(HASH_A)).resolves.toBeNull();
            expect(h.storage.ops).toEqual([`get ${KEY_A}`]);
        });

        it("reads the record stored under the hash", async () => {
            const h = harness();
            h.storage.map.set(KEY_A, JSON.stringify(SEND_A));
            await expect(h.history.read(HASH_A)).resolves.toEqual(SEND_A);
        });

        it("reads what a previous instance wrote, through an asynchronous storage", async () => {
            const storage = new AsyncInMemorySignerStorage();
            await harness(storage).history.update(HASH_B, () => RECEIVE_B);
            await expect(harness(storage).history.read(HASH_B)).resolves.toEqual(RECEIVE_B);
        });

        it.each([
            ["a prefixed hash", `0x${HASH_A}`],
            ["an uppercase hash", HASH_A.toUpperCase()],
            ["a 31-byte hash", "aa".repeat(31)],
            ["a 33-byte hash", "aa".repeat(33)],
            ["an empty hash", ""],
        ])("refuses %s before touching the storage", async (_, hash) => {
            const h = harness();
            await expect(h.history.read(hash)).rejects.toThrow(new TypeError("paymentHash must be 32 bytes of lowercase hex"));
            expect(h.storage.ops).toEqual([]);
        });

        it("throws on a stored value that is not JSON", async () => {
            const h = harness();
            h.storage.map.set(KEY_A, "{");
            await expect(h.history.read(HASH_A)).rejects.toThrow(new TypeError(`stored value at ${KEY_A} is not valid JSON`));
        });

        it("throws on a stored value that is not a payment record", async () => {
            const h = harness();
            h.storage.map.set(KEY_A, JSON.stringify({ ...SEND_A, feeShannons: "7" }));
            await expect(h.history.read(HASH_A)).rejects.toThrow(new TypeError(`stored value at ${KEY_A} is not a payment record`));
        });

        it("throws on a payment record stored under another hash's key", async () => {
            const h = harness();
            h.storage.map.set(KEY_B, JSON.stringify(SEND_A));
            await expect(h.history.read(HASH_B)).rejects.toThrow(new TypeError(`stored value at ${KEY_B} is not a payment record`));
        });
    });

    describe("update", () => {
        it("writes the record first, then the index, and hands back the record", async () => {
            const h = harness();
            const seen: (StoredPaymentRecord | null)[] = [];
            await expect(
                h.history.update(HASH_A, (current) => {
                    seen.push(current);
                    return SEND_A;
                }),
            ).resolves.toBe(SEND_A);
            expect(seen).toEqual([null]);
            expect(h.storage.ops).toEqual([`get ${KEY_A}`, `set ${KEY_A}`, `get ${INDEX_KEY}`, `set ${INDEX_KEY}`]);
            expect(h.storage.map.get(KEY_A)).toBe(JSON.stringify(SEND_A));
            expect(h.storage.map.get(INDEX_KEY)).toBe(`{"version":1,"entries":[{"paymentHash":"${HASH_A}","createdAtMs":1000}]}`);
            expect([...h.storage.map.keys()]).toEqual([KEY_A, INDEX_KEY]);
        });

        it("hands the updater the stored record, and rewrites it without touching an index already right", async () => {
            const h = harness();
            await h.history.update(HASH_A, () => SEND_A);
            h.storage.ops.length = 0;
            const seen: (StoredPaymentRecord | null)[] = [];
            await expect(
                h.history.update(HASH_A, (current) => {
                    seen.push(current);
                    return COMPLETED_A;
                }),
            ).resolves.toBe(COMPLETED_A);
            expect(seen).toEqual([SEND_A]);
            expect(h.storage.ops).toEqual([`get ${KEY_A}`, `set ${KEY_A}`, `get ${INDEX_KEY}`]);
            await expect(h.history.read(HASH_A)).resolves.toEqual(COMPLETED_A);
        });

        it("writes no record when the updater hands back the one it was given", async () => {
            const h = harness();
            await h.history.update(HASH_A, () => SEND_A);
            h.storage.ops.length = 0;
            await expect(h.history.update(HASH_A, (current) => current)).resolves.toEqual(SEND_A);
            expect(h.storage.ops).toEqual([`get ${KEY_A}`, `get ${INDEX_KEY}`]);
        });

        it("places in the index, on its next write even unchanged, a record a stop left out of it", async () => {
            const h = harness();
            h.storage.map.set(KEY_A, JSON.stringify(SEND_A));
            await expect(h.history.update(HASH_A, (current) => current)).resolves.toEqual(SEND_A);
            expect(h.storage.ops).toEqual([`get ${KEY_A}`, `get ${INDEX_KEY}`, `set ${INDEX_KEY}`]);
            await expect(h.history.list(10, 0)).resolves.toEqual([SEND_A]);
        });

        it("hands back null and writes nothing when the history holds no record and the updater keeps it so", async () => {
            const h = harness();
            await expect(h.history.update(HASH_A, () => null)).resolves.toBeNull();
            expect(h.storage.ops).toEqual([`get ${KEY_A}`]);
            expect(h.storage.map.size).toBe(0);
        });

        it("moves the index entry when the record's creation time changes", async () => {
            const h = await seeded();
            const retried = { ...SEND_A, createdAtMs: 4000 };
            await h.history.update(HASH_A, () => retried);
            expect(h.storage.map.get(INDEX_KEY)).toBe(
                `{"version":1,"entries":[{"paymentHash":"${HASH_A}","createdAtMs":4000},{"paymentHash":"${HASH_B}","createdAtMs":3000},{"paymentHash":"${HASH_C}","createdAtMs":2000}]}`,
            );
            await expect(h.history.list(10, 0)).resolves.toEqual([retried, RECEIVE_B, SEND_C]);
        });

        it("refuses an updated record that is not a payment record, writing nothing", async () => {
            const h = harness();
            await expect(h.history.update(HASH_A, () => ({ ...SEND_A, amountShannons: "0" }))).rejects.toThrow(
                new TypeError("updated record is not a valid payment record"),
            );
            expect(h.storage.ops).toEqual([`get ${KEY_A}`]);
        });

        it("refuses to delete a record, writing nothing", async () => {
            const h = harness();
            await h.history.update(HASH_A, () => SEND_A);
            h.storage.ops.length = 0;
            await expect(h.history.update(HASH_A, () => null)).rejects.toThrow(
                new TypeError("updated record is not a valid payment record"),
            );
            expect(h.storage.ops).toEqual([`get ${KEY_A}`]);
            await expect(h.history.read(HASH_A)).resolves.toEqual(SEND_A);
        });

        it("refuses an updated record of another hash, writing nothing", async () => {
            const h = harness();
            await expect(h.history.update(HASH_B, () => SEND_A)).rejects.toThrow(
                new TypeError(`updated record does not belong at ${KEY_B}`),
            );
            expect(h.storage.ops).toEqual([`get ${KEY_B}`]);
            expect(h.storage.map.size).toBe(0);
        });

        it("throws on a corrupt stored record without calling the updater", async () => {
            const h = harness();
            h.storage.map.set(KEY_A, "[]");
            const update = jest.fn(() => SEND_A);
            await expect(h.history.update(HASH_A, update)).rejects.toThrow(
                new TypeError(`stored value at ${KEY_A} is not a payment record`),
            );
            expect(update).not.toHaveBeenCalled();
        });

        it("throws on a corrupt index after writing the record", async () => {
            const h = harness();
            h.storage.map.set(INDEX_KEY, JSON.stringify({ version: 2, entries: [] }));
            await expect(h.history.update(HASH_A, () => SEND_A)).rejects.toThrow(
                new TypeError(`stored value at ${INDEX_KEY} is not a payment history index`),
            );
            expect(h.storage.ops).toEqual([`get ${KEY_A}`, `set ${KEY_A}`, `get ${INDEX_KEY}`]);
        });

        it.each([
            ["a prefixed hash", `0x${HASH_A}`],
            ["an uppercase hash", HASH_A.toUpperCase()],
            ["a 31-byte hash", "aa".repeat(31)],
        ])("refuses %s before touching the storage or calling the updater", async (_, hash) => {
            const h = harness();
            const update = jest.fn(() => SEND_A);
            await expect(h.history.update(hash, update)).rejects.toThrow(new TypeError("paymentHash must be 32 bytes of lowercase hex"));
            expect(update).not.toHaveBeenCalled();
            expect(h.storage.ops).toEqual([]);
        });

        it("serializes concurrent updates of one hash over an asynchronous storage", async () => {
            const h = harness(new AsyncInMemorySignerStorage());
            const seen: (StoredPaymentRecord | null)[] = [];
            await Promise.all([
                h.history.update(HASH_A, (current) => {
                    seen.push(current);
                    return SEND_A;
                }),
                h.history.update(HASH_A, (current) => {
                    seen.push(current);
                    return COMPLETED_A;
                }),
            ]);
            expect(seen).toEqual([null, SEND_A]);
            await expect(h.history.list(10, 0)).resolves.toEqual([COMPLETED_A]);
        });
    });

    describe("list", () => {
        it("lists nothing when the history was never written, reading only the index", async () => {
            const h = harness();
            await expect(h.history.list(10, 0)).resolves.toEqual([]);
            expect(h.storage.ops).toEqual([`get ${INDEX_KEY}`]);
        });

        it("lists newest first, whatever order they were written in", async () => {
            const h = await seeded();
            await expect(h.history.list(10, 0)).resolves.toEqual([RECEIVE_B, SEND_C, SEND_A]);
            expect(h.storage.ops).toEqual([`get ${INDEX_KEY}`, `get ${KEY_B}`, `get ${KEY_C}`, `get ${KEY_A}`]);
        });

        it("lists through an asynchronous storage", async () => {
            const h = await seeded(new AsyncInMemorySignerStorage());
            await expect(h.history.list(10, 0)).resolves.toEqual([RECEIVE_B, SEND_C, SEND_A]);
        });

        it.each([
            ["an exact fit", 3, 0, ["B", "C", "A"]],
            ["the first page", 2, 0, ["B", "C"]],
            ["a page shifted by one", 2, 1, ["C", "A"]],
            ["the last record alone", 1, 2, ["A"]],
            ["a page cut short at the end", 5, 2, ["A"]],
            ["a page starting at the end", 5, 3, []],
            ["a page past the end", 5, 10, []],
            ["a page of no records", 0, 0, []],
            ["a page of no records inside the history", 0, 1, []],
        ])("pages %s (limit %p, offset %p)", async (_, limit, offset, expected) => {
            const h = await seeded();
            const records: Record<string, StoredPaymentRecord> = { A: SEND_A, B: RECEIVE_B, C: SEND_C };
            await expect(h.history.list(limit, offset)).resolves.toEqual(expected.map((name) => records[name]));
        });

        it("reads only the records of the page", async () => {
            const h = await seeded();
            await h.history.list(1, 1);
            expect(h.storage.ops).toEqual([`get ${INDEX_KEY}`, `get ${KEY_C}`]);
        });

        it("orders records created at the same time by hash", async () => {
            const h = harness();
            const atOnce = { ...RECEIVE_B, createdAtMs: 1000 };
            await h.history.update(HASH_B, () => atOnce);
            await h.history.update(HASH_A, () => SEND_A);
            await expect(h.history.list(10, 0)).resolves.toEqual([SEND_A, atOnce]);
        });

        it("throws when the index lists a hash whose record is missing", async () => {
            const h = await seeded();
            h.storage.map.delete(KEY_C);
            await expect(h.history.list(10, 0)).rejects.toThrow(
                new TypeError(`the payment history lists 0x${HASH_C}, whose record is missing`),
            );
        });

        it("lists a page that leaves out the hash whose record is missing", async () => {
            const h = await seeded();
            h.storage.map.delete(KEY_C);
            await expect(h.history.list(1, 0)).resolves.toEqual([RECEIVE_B]);
        });

        it("throws on a corrupt index", async () => {
            const h = harness();
            h.storage.map.set(
                INDEX_KEY,
                JSON.stringify({
                    version: 1,
                    entries: [
                        { paymentHash: HASH_A, createdAtMs: 1000 },
                        { paymentHash: HASH_B, createdAtMs: 3000 },
                    ],
                }),
            );
            await expect(h.history.list(10, 0)).rejects.toThrow(
                new TypeError(`stored value at ${INDEX_KEY} is not a payment history index`),
            );
        });

        it("throws on a corrupt record the index lists", async () => {
            const h = await seeded();
            h.storage.map.set(KEY_B, JSON.stringify({ ...RECEIVE_B, maxFeeShannons: "500" }));
            await expect(h.history.list(10, 0)).rejects.toThrow(new TypeError(`stored value at ${KEY_B} is not a payment record`));
        });
    });
});
