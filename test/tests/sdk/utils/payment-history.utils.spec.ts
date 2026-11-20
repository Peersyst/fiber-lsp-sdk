import type { PaymentHistoryIndex, StoredPaymentRecord } from "../../../../src/sdk";
import {
    PAYMENT_HISTORY_RECORD_VERSION,
    SDK_PAYMENT_DIRECTIONS,
    SDK_PAYMENT_RECORD_STATUSES,
    arrivedReceiveRecord,
    assertPaymentHistoryIndex,
    assertStoredPaymentRecord,
    emptyPaymentHistoryIndex,
    isPaymentHistoryIndex,
    isStoredPaymentRecord,
    pendingSendRecord,
    placeInPaymentHistoryIndex,
    settlePaymentRecord,
    toSdkPaymentRecord,
} from "../../../../src/sdk";

const HASH = "ab".repeat(32);
const HASH_1 = "11".repeat(32);
const HASH_2 = "22".repeat(32);
const HASH_3 = "33".repeat(32);
const INVOICE = "fibt1000000001pcsaug0p0exgfw0pnm6vk0rnt4xefskmrz0g";
const RECEIVE_INVOICE = "fibt200000001pcsaug0p0exgfw0pnm6vkkya5ul6wxurhh09qf";
const U128_MAX = "340282366920938463463374607431768211455";
const U128_OVER = "340282366920938463463374607431768211456";

const PENDING_SEND: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH}`,
    direction: "send",
    status: "pending",
    amountShannons: "100000",
    invoice: INVOICE,
    description: "coffee",
    maxFeeShannons: "500",
    feeShannons: null,
    failedReason: null,
    createdAtMs: 1700000000000,
    settledAtMs: null,
};

const COMPLETED_SEND: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH}`,
    direction: "send",
    status: "completed",
    amountShannons: "100000",
    invoice: INVOICE,
    description: "coffee",
    maxFeeShannons: "500",
    feeShannons: "7",
    failedReason: null,
    createdAtMs: 1700000000000,
    settledAtMs: 1700000005000,
};

const FAILED_SEND: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH}`,
    direction: "send",
    status: "failed",
    amountShannons: "100000",
    invoice: INVOICE,
    description: "coffee",
    maxFeeShannons: "500",
    feeShannons: null,
    failedReason: "no path found",
    createdAtMs: 1700000000000,
    settledAtMs: 1700000003000,
};

const PENDING_RECEIVE: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_1}`,
    direction: "receive",
    status: "pending",
    amountShannons: "200000",
    invoice: RECEIVE_INVOICE,
    description: null,
    maxFeeShannons: null,
    feeShannons: null,
    failedReason: null,
    createdAtMs: 1700000010000,
    settledAtMs: null,
};

const COMPLETED_RECEIVE: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_1}`,
    direction: "receive",
    status: "completed",
    amountShannons: "200000",
    invoice: RECEIVE_INVOICE,
    description: null,
    maxFeeShannons: null,
    feeShannons: "0",
    failedReason: null,
    createdAtMs: 1700000010000,
    settledAtMs: 1700000012000,
};

const FAILED_RECEIVE: StoredPaymentRecord = {
    version: 1,
    paymentHashHex: `0x${HASH_1}`,
    direction: "receive",
    status: "failed",
    amountShannons: "200000",
    invoice: RECEIVE_INVOICE,
    description: null,
    maxFeeShannons: null,
    feeShannons: null,
    failedReason: "the invoice expired",
    createdAtMs: 1700000010000,
    settledAtMs: 1700000090000,
};

const INDEX: PaymentHistoryIndex = {
    version: 1,
    entries: [
        { paymentHash: HASH_2, createdAtMs: 300 },
        { paymentHash: HASH_1, createdAtMs: 200 },
        { paymentHash: HASH_3, createdAtMs: 200 },
        { paymentHash: HASH, createdAtMs: 100 },
    ],
};

const NOW = 1700000099000;

function without(record: object, field: string): Record<string, unknown> {
    return Object.fromEntries(Object.entries(record).filter(([key]) => key !== field));
}

describe("payment history utils", () => {
    it("pins the version, the directions and the statuses", () => {
        expect(PAYMENT_HISTORY_RECORD_VERSION).toBe(1);
        expect(SDK_PAYMENT_DIRECTIONS).toEqual(["send", "receive"]);
        expect(SDK_PAYMENT_RECORD_STATUSES).toEqual(["pending", "completed", "failed"]);
    });

    describe("isStoredPaymentRecord", () => {
        it.each([
            ["a pending send", PENDING_SEND],
            ["a completed send", COMPLETED_SEND],
            ["a failed send", FAILED_SEND],
            ["a pending receive", PENDING_RECEIVE],
            ["a completed receive", COMPLETED_RECEIVE],
            ["a failed receive", FAILED_RECEIVE],
            ["a record with extra fields", { ...PENDING_SEND, extra: 1, note: "kept" }],
            ["an empty description", { ...PENDING_SEND, description: "" }],
            ["a null description", { ...PENDING_SEND, description: null }],
            ["a zero fee budget", { ...PENDING_SEND, maxFeeShannons: "0" }],
            ["the largest fee budget", { ...PENDING_SEND, maxFeeShannons: U128_MAX }],
            ["the largest amount", { ...PENDING_SEND, amountShannons: U128_MAX }],
            ["an amount of one shannon", { ...PENDING_SEND, amountShannons: "1" }],
            ["a completed send with no fee charged", { ...COMPLETED_SEND, feeShannons: "0" }],
            ["a completed send with the largest fee", { ...COMPLETED_SEND, feeShannons: U128_MAX }],
            ["a failed send with an empty reason", { ...FAILED_SEND, failedReason: "" }],
            ["a creation at time zero", { ...PENDING_SEND, createdAtMs: 0 }],
            ["a creation at the largest safe time", { ...PENDING_SEND, createdAtMs: Number.MAX_SAFE_INTEGER }],
            ["a settlement at time zero", { ...COMPLETED_SEND, settledAtMs: 0 }],
            ["a settlement at the largest safe time", { ...FAILED_SEND, settledAtMs: Number.MAX_SAFE_INTEGER }],
        ])("takes %s", (_, record) => {
            expect(isStoredPaymentRecord(record)).toBe(true);
            expect(() => assertStoredPaymentRecord("record", record)).not.toThrow();
        });

        it.each<[string, unknown]>([
            ["null", null],
            ["undefined", undefined],
            ["an array", [PENDING_SEND]],
            ["a string", JSON.stringify(PENDING_SEND)],
            ["a number", 1],
            ["version 2", { ...PENDING_SEND, version: 2 }],
            ["version 0", { ...PENDING_SEND, version: 0 }],
            ["version as a string", { ...PENDING_SEND, version: "1" }],
            ["no version", without(PENDING_SEND, "version")],
            ["no hash", without(PENDING_SEND, "paymentHashHex")],
            ["an unprefixed hash", { ...PENDING_SEND, paymentHashHex: HASH }],
            ["an uppercase hash", { ...PENDING_SEND, paymentHashHex: `0x${HASH.toUpperCase()}` }],
            ["an uppercase prefix", { ...PENDING_SEND, paymentHashHex: `0X${HASH}` }],
            ["a 31-byte hash", { ...PENDING_SEND, paymentHashHex: `0x${"ab".repeat(31)}` }],
            ["a 33-byte hash", { ...PENDING_SEND, paymentHashHex: `0x${"ab".repeat(33)}` }],
            ["an odd-length hash", { ...PENDING_SEND, paymentHashHex: `0x${HASH}a` }],
            ["a non-hex hash", { ...PENDING_SEND, paymentHashHex: `0x${"zz".repeat(32)}` }],
            ["a hash as a number", { ...PENDING_SEND, paymentHashHex: 1 }],
            ["an unknown direction", { ...PENDING_SEND, direction: "sent" }],
            ["a capitalized direction", { ...PENDING_SEND, direction: "Send" }],
            ["no direction", without(PENDING_SEND, "direction")],
            ["a receive's record under an unknown direction", { ...COMPLETED_RECEIVE, direction: "received" }],
            ["a receive's record under no direction", without(COMPLETED_RECEIVE, "direction")],
            ["an unknown status", { ...PENDING_SEND, status: "inflight" }],
            ["a capitalized status", { ...PENDING_SEND, status: "Pending" }],
            ["no status", without(PENDING_SEND, "status")],
            ["a zero amount", { ...PENDING_SEND, amountShannons: "0" }],
            ["a negative amount", { ...PENDING_SEND, amountShannons: "-1" }],
            ["an amount with a leading zero", { ...PENDING_SEND, amountShannons: "0100000" }],
            ["a fractional amount", { ...PENDING_SEND, amountShannons: "1.5" }],
            ["an amount above u128", { ...PENDING_SEND, amountShannons: U128_OVER }],
            ["an amount as a number", { ...PENDING_SEND, amountShannons: 100000 }],
            ["no amount", without(PENDING_SEND, "amountShannons")],
            ["an empty invoice", { ...PENDING_SEND, invoice: "" }],
            ["an invoice as a number", { ...PENDING_SEND, invoice: 1 }],
            ["no invoice", without(PENDING_SEND, "invoice")],
            ["a description as a number", { ...PENDING_SEND, description: 1 }],
            ["no description", without(PENDING_SEND, "description")],
            ["a send without a fee budget", { ...PENDING_SEND, maxFeeShannons: null }],
            ["a send with no fee budget field", without(PENDING_SEND, "maxFeeShannons")],
            ["a send with a negative fee budget", { ...PENDING_SEND, maxFeeShannons: "-1" }],
            ["a send with a fee budget with a leading zero", { ...PENDING_SEND, maxFeeShannons: "0500" }],
            ["a send with a fee budget above u128", { ...PENDING_SEND, maxFeeShannons: U128_OVER }],
            ["a send with a fee budget as a number", { ...PENDING_SEND, maxFeeShannons: 500 }],
            ["a receive with a fee budget", { ...PENDING_RECEIVE, maxFeeShannons: "500" }],
            ["a receive with a zero fee budget", { ...PENDING_RECEIVE, maxFeeShannons: "0" }],
            ["a receive with no fee budget field", without(PENDING_RECEIVE, "maxFeeShannons")],
            ["a negative creation time", { ...PENDING_SEND, createdAtMs: -1 }],
            ["a fractional creation time", { ...PENDING_SEND, createdAtMs: 1.5 }],
            ["an unsafe creation time", { ...PENDING_SEND, createdAtMs: Number.MAX_SAFE_INTEGER + 1 }],
            ["a creation time as a string", { ...PENDING_SEND, createdAtMs: "1700000000000" }],
            ["no creation time", without(PENDING_SEND, "createdAtMs")],
            ["a pending send with a fee", { ...PENDING_SEND, feeShannons: "7" }],
            ["a pending send with a zero fee", { ...PENDING_SEND, feeShannons: "0" }],
            ["a pending send with no fee field", without(PENDING_SEND, "feeShannons")],
            ["a pending send with a reason", { ...PENDING_SEND, failedReason: "no path found" }],
            ["a pending send with an empty reason", { ...PENDING_SEND, failedReason: "" }],
            ["a pending send with no reason field", without(PENDING_SEND, "failedReason")],
            ["a pending send with a settlement", { ...PENDING_SEND, settledAtMs: 1700000005000 }],
            ["a pending send settled at time zero", { ...PENDING_SEND, settledAtMs: 0 }],
            ["a pending send with no settlement field", without(PENDING_SEND, "settledAtMs")],
            ["a pending receive with a zero fee", { ...PENDING_RECEIVE, feeShannons: "0" }],
            ["a pending receive with a reason", { ...PENDING_RECEIVE, failedReason: "the invoice expired" }],
            ["a pending receive with a settlement", { ...PENDING_RECEIVE, settledAtMs: 1700000012000 }],
            ["a completed send without a settlement", { ...COMPLETED_SEND, settledAtMs: null }],
            ["a completed send with no settlement field", without(COMPLETED_SEND, "settledAtMs")],
            ["a completed send with a negative settlement", { ...COMPLETED_SEND, settledAtMs: -1 }],
            ["a completed send with a fractional settlement", { ...COMPLETED_SEND, settledAtMs: 1.5 }],
            ["a completed send with an unsafe settlement", { ...COMPLETED_SEND, settledAtMs: Number.MAX_SAFE_INTEGER + 1 }],
            ["a completed send with a settlement as a string", { ...COMPLETED_SEND, settledAtMs: "1700000005000" }],
            ["a failed send without a settlement", { ...FAILED_SEND, settledAtMs: null }],
            ["a failed send with a negative settlement", { ...FAILED_SEND, settledAtMs: -1 }],
            ["a failed receive without a settlement", { ...FAILED_RECEIVE, settledAtMs: null }],
            ["a failed send with a fee", { ...FAILED_SEND, feeShannons: "7" }],
            ["a failed send with a zero fee", { ...FAILED_SEND, feeShannons: "0" }],
            ["a failed send with no fee field", without(FAILED_SEND, "feeShannons")],
            ["a failed send without a reason", { ...FAILED_SEND, failedReason: null }],
            ["a failed send with a reason as a number", { ...FAILED_SEND, failedReason: 1 }],
            ["a failed send with no reason field", without(FAILED_SEND, "failedReason")],
            ["a failed receive with a zero fee", { ...FAILED_RECEIVE, feeShannons: "0" }],
            ["a failed receive without a reason", { ...FAILED_RECEIVE, failedReason: null }],
            ["a completed send without a fee", { ...COMPLETED_SEND, feeShannons: null }],
            ["a completed send with no fee field", without(COMPLETED_SEND, "feeShannons")],
            ["a completed send with a negative fee", { ...COMPLETED_SEND, feeShannons: "-7" }],
            ["a completed send with a fee with a leading zero", { ...COMPLETED_SEND, feeShannons: "07" }],
            ["a completed send with a fee above u128", { ...COMPLETED_SEND, feeShannons: U128_OVER }],
            ["a completed send with a fee as a number", { ...COMPLETED_SEND, feeShannons: 7 }],
            ["a completed send with a reason", { ...COMPLETED_SEND, failedReason: "no path found" }],
            ["a completed send with an empty reason", { ...COMPLETED_SEND, failedReason: "" }],
            ["a completed send with no reason field", without(COMPLETED_SEND, "failedReason")],
            ["a completed receive with a fee", { ...COMPLETED_RECEIVE, feeShannons: "1" }],
            ["a completed receive with a zero fee spelled twice", { ...COMPLETED_RECEIVE, feeShannons: "00" }],
            ["a completed receive with a zero fee as a number", { ...COMPLETED_RECEIVE, feeShannons: 0 }],
            ["a completed receive without a fee", { ...COMPLETED_RECEIVE, feeShannons: null }],
            ["a completed receive with a reason", { ...COMPLETED_RECEIVE, failedReason: "the invoice expired" }],
        ])("refuses %s", (_, value) => {
            expect(isStoredPaymentRecord(value)).toBe(false);
            expect(() => assertStoredPaymentRecord("stored record", value)).toThrow(
                new TypeError("stored record is not a valid payment record"),
            );
        });
    });

    describe("isPaymentHistoryIndex", () => {
        it.each<[string, unknown]>([
            ["an empty index", { version: 1, entries: [] }],
            ["a single entry", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: 0 }] }],
            ["entries newest first, ties by hash", INDEX],
            ["entries at the largest safe time", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: Number.MAX_SAFE_INTEGER }] }],
            ["extra fields on the index", { ...INDEX, extra: true }],
            ["extra fields on an entry", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: 1, extra: "kept" }] }],
        ])("takes %s", (_, index) => {
            expect(isPaymentHistoryIndex(index)).toBe(true);
            expect(() => assertPaymentHistoryIndex("index", index)).not.toThrow();
        });

        it.each<[string, unknown]>([
            ["null", null],
            ["an array", [INDEX]],
            ["a string", JSON.stringify(INDEX)],
            ["version 2", { ...INDEX, version: 2 }],
            ["version as a string", { ...INDEX, version: "1" }],
            ["no version", { entries: [] }],
            ["no entries", { version: 1 }],
            ["entries as an object", { version: 1, entries: {} }],
            ["entries as null", { version: 1, entries: null }],
            ["a null entry", { version: 1, entries: [null] }],
            ["an array entry", { version: 1, entries: [[HASH, 1]] }],
            ["an entry with a prefixed hash", { version: 1, entries: [{ paymentHash: `0x${HASH}`, createdAtMs: 1 }] }],
            ["an entry with an uppercase hash", { version: 1, entries: [{ paymentHash: HASH.toUpperCase(), createdAtMs: 1 }] }],
            ["an entry with a 31-byte hash", { version: 1, entries: [{ paymentHash: "ab".repeat(31), createdAtMs: 1 }] }],
            ["an entry with a 33-byte hash", { version: 1, entries: [{ paymentHash: "ab".repeat(33), createdAtMs: 1 }] }],
            ["an entry with a hash as a number", { version: 1, entries: [{ paymentHash: 1, createdAtMs: 1 }] }],
            ["an entry with no hash", { version: 1, entries: [{ createdAtMs: 1 }] }],
            ["an entry with a negative time", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: -1 }] }],
            ["an entry with a fractional time", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: 1.5 }] }],
            ["an entry with an unsafe time", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: Number.MAX_SAFE_INTEGER + 1 }] }],
            ["an entry with a time as a string", { version: 1, entries: [{ paymentHash: HASH, createdAtMs: "1" }] }],
            ["an entry with no time", { version: 1, entries: [{ paymentHash: HASH }] }],
            ["a bad entry after good ones", { version: 1, entries: [...INDEX.entries, { paymentHash: HASH_1, createdAtMs: -1 }] }],
            [
                "entries oldest first",
                {
                    version: 1,
                    entries: [
                        { paymentHash: HASH_1, createdAtMs: 100 },
                        { paymentHash: HASH_2, createdAtMs: 200 },
                    ],
                },
            ],
            [
                "entries out of order only at the end",
                {
                    version: 1,
                    entries: [
                        { paymentHash: HASH_1, createdAtMs: 300 },
                        { paymentHash: HASH_2, createdAtMs: 100 },
                        { paymentHash: HASH_3, createdAtMs: 200 },
                    ],
                },
            ],
            [
                "a tie ordered against the hash",
                {
                    version: 1,
                    entries: [
                        { paymentHash: HASH_3, createdAtMs: 200 },
                        { paymentHash: HASH_1, createdAtMs: 200 },
                    ],
                },
            ],
            [
                "an adjacent duplicate hash at one time",
                {
                    version: 1,
                    entries: [
                        { paymentHash: HASH_1, createdAtMs: 200 },
                        { paymentHash: HASH_1, createdAtMs: 200 },
                    ],
                },
            ],
            [
                "an adjacent duplicate hash at two times",
                {
                    version: 1,
                    entries: [
                        { paymentHash: HASH_1, createdAtMs: 300 },
                        { paymentHash: HASH_1, createdAtMs: 200 },
                    ],
                },
            ],
            [
                "a non-adjacent duplicate hash, otherwise in order",
                {
                    version: 1,
                    entries: [
                        { paymentHash: HASH_1, createdAtMs: 300 },
                        { paymentHash: HASH_2, createdAtMs: 200 },
                        { paymentHash: HASH_1, createdAtMs: 100 },
                    ],
                },
            ],
        ])("refuses %s", (_, value) => {
            expect(isPaymentHistoryIndex(value)).toBe(false);
            expect(() => assertPaymentHistoryIndex("stored index", value)).toThrow(
                new TypeError("stored index is not a valid payment history index"),
            );
        });
    });

    it("builds an empty index, a new object each time", () => {
        expect(emptyPaymentHistoryIndex()).toEqual({ version: 1, entries: [] });
        expect(emptyPaymentHistoryIndex()).not.toBe(emptyPaymentHistoryIndex());
        expect(emptyPaymentHistoryIndex().entries).not.toBe(emptyPaymentHistoryIndex().entries);
    });

    describe("placeInPaymentHistoryIndex", () => {
        it("starts an index that was never written, copying the entry", () => {
            const entry = { paymentHash: HASH, createdAtMs: 100 };
            const placed = placeInPaymentHistoryIndex(null, entry);
            expect(placed).toEqual({ version: 1, entries: [{ paymentHash: HASH, createdAtMs: 100 }] });
            expect(placed?.entries[0]).not.toBe(entry);
        });

        it.each([
            ["first when newest", { paymentHash: HASH, createdAtMs: 400 }, [HASH, HASH_2, HASH_1, HASH_3]],
            ["last when oldest", { paymentHash: "44".repeat(32), createdAtMs: 50 }, [HASH_2, HASH_1, HASH_3, HASH, "44".repeat(32)]],
            ["between older and newer", { paymentHash: HASH, createdAtMs: 250 }, [HASH_2, HASH, HASH_1, HASH_3]],
            [
                "before a tie with a greater hash",
                { paymentHash: "00".repeat(32), createdAtMs: 200 },
                [HASH_2, "00".repeat(32), HASH_1, HASH_3, HASH],
            ],
            ["between ties by hash", { paymentHash: "2f".repeat(32), createdAtMs: 200 }, [HASH_2, HASH_1, "2f".repeat(32), HASH_3, HASH]],
            [
                "after a tie with a lesser hash",
                { paymentHash: "ff".repeat(32), createdAtMs: 200 },
                [HASH_2, HASH_1, HASH_3, "ff".repeat(32), HASH],
            ],
        ])("places a new entry %s, leaving the given index untouched", (_, entry, order) => {
            const before = JSON.stringify(INDEX);
            const placed = placeInPaymentHistoryIndex(INDEX, entry);
            expect(placed?.entries.map(({ paymentHash }) => paymentHash)).toEqual(order);
            expect(placed?.entries).toContainEqual(entry);
            expect(isPaymentHistoryIndex(placed)).toBe(true);
            expect(JSON.stringify(INDEX)).toBe(before);
        });

        it("hands back the very index given when the entry already sits at its time", () => {
            expect(placeInPaymentHistoryIndex(INDEX, { paymentHash: HASH_1, createdAtMs: 200 })).toBe(INDEX);
            expect(placeInPaymentHistoryIndex(INDEX, { paymentHash: HASH, createdAtMs: 100 })).toBe(INDEX);
        });

        it("moves an entry whose creation time changed, keeping one entry per hash", () => {
            expect(placeInPaymentHistoryIndex(INDEX, { paymentHash: HASH_2, createdAtMs: 150 })).toEqual({
                version: 1,
                entries: [
                    { paymentHash: HASH_1, createdAtMs: 200 },
                    { paymentHash: HASH_3, createdAtMs: 200 },
                    { paymentHash: HASH_2, createdAtMs: 150 },
                    { paymentHash: HASH, createdAtMs: 100 },
                ],
            });
            expect(placeInPaymentHistoryIndex(INDEX, { paymentHash: HASH, createdAtMs: 500 })).toEqual({
                version: 1,
                entries: [
                    { paymentHash: HASH, createdAtMs: 500 },
                    { paymentHash: HASH_2, createdAtMs: 300 },
                    { paymentHash: HASH_1, createdAtMs: 200 },
                    { paymentHash: HASH_3, createdAtMs: 200 },
                ],
            });
        });

        it("keeps the index's other fields", () => {
            const index = { ...INDEX, extra: "kept" };
            expect(placeInPaymentHistoryIndex(index, { paymentHash: HASH, createdAtMs: 500 })).toMatchObject({ version: 1, extra: "kept" });
        });
    });

    describe("pendingSendRecord", () => {
        it("builds a pending send from the invoice and the budget, created now", () => {
            const record = pendingSendRecord(
                { paymentHashHex: `0x${HASH}`, amountShannons: "100000", invoice: INVOICE, description: "coffee", maxFeeShannons: "500" },
                1700000000000,
            );
            expect(record).toEqual(PENDING_SEND);
            expect(isStoredPaymentRecord(record)).toBe(true);
        });

        it("keeps a missing description as null", () => {
            expect(
                pendingSendRecord(
                    { paymentHashHex: `0x${HASH}`, amountShannons: "1", invoice: INVOICE, description: null, maxFeeShannons: "0" },
                    0,
                ),
            ).toEqual({
                version: 1,
                paymentHashHex: `0x${HASH}`,
                direction: "send",
                status: "pending",
                amountShannons: "1",
                invoice: INVOICE,
                description: null,
                maxFeeShannons: "0",
                feeShannons: null,
                failedReason: null,
                createdAtMs: 0,
                settledAtMs: null,
            });
        });
    });

    describe("arrivedReceiveRecord", () => {
        const RECEIVE = { paymentHashHex: `0x${HASH_1}`, amountShannons: "200000", invoice: RECEIVE_INVOICE, description: null };

        it("builds a pending receive with no fee budget, created now, when none arrived before", () => {
            const record = arrivedReceiveRecord(null, RECEIVE, 1700000010000);
            expect(record).toEqual(PENDING_RECEIVE);
            expect(isStoredPaymentRecord(record)).toBe(true);
        });

        it("keeps the invoice's description", () => {
            expect(arrivedReceiveRecord(null, { ...RECEIVE, description: "rent" }, 5)).toEqual({
                ...PENDING_RECEIVE,
                description: "rent",
                createdAtMs: 5,
            });
        });

        it.each([
            ["a pending receive", PENDING_RECEIVE],
            ["a completed receive", COMPLETED_RECEIVE],
            ["a failed receive", FAILED_RECEIVE],
        ])("keeps %s already there, the very same object", (_, current) => {
            expect(arrivedReceiveRecord(current, { ...RECEIVE, amountShannons: "999" }, NOW)).toBe(current);
        });
    });

    describe("settlePaymentRecord", () => {
        it.each([
            ["completed", { status: "completed", feeShannons: "7" }],
            ["failed", { status: "failed", reason: "no path found" }],
        ] as const)("leaves no record as none when the payment %s", (_, outcome) => {
            expect(settlePaymentRecord(null, outcome, NOW)).toBeNull();
        });

        it("completes a pending send with the fee charged, settled now", () => {
            const settled = settlePaymentRecord(PENDING_SEND, { status: "completed", feeShannons: "7" }, 1700000005000);
            expect(settled).toEqual(COMPLETED_SEND);
            expect(isStoredPaymentRecord(settled)).toBe(true);
            expect(PENDING_SEND.status).toBe("pending");
        });

        it("fails a pending send with the reason, settled now", () => {
            const settled = settlePaymentRecord(PENDING_SEND, { status: "failed", reason: "no path found" }, 1700000003000);
            expect(settled).toEqual(FAILED_SEND);
            expect(isStoredPaymentRecord(settled)).toBe(true);
        });

        it("completes a pending receive, settled now", () => {
            const settled = settlePaymentRecord(PENDING_RECEIVE, { status: "completed", feeShannons: "0" }, 1700000012000);
            expect(settled).toEqual(COMPLETED_RECEIVE);
            expect(isStoredPaymentRecord(settled)).toBe(true);
        });

        it("fails a pending receive with the reason, settled now", () => {
            const settled = settlePaymentRecord(PENDING_RECEIVE, { status: "failed", reason: "the invoice expired" }, 1700000090000);
            expect(settled).toEqual(FAILED_RECEIVE);
            expect(isStoredPaymentRecord(settled)).toBe(true);
        });

        it("turns a failed send completed, clearing its reason and settling it again now", () => {
            const settled = settlePaymentRecord(FAILED_SEND, { status: "completed", feeShannons: "9" }, NOW);
            expect(settled).toEqual({ ...COMPLETED_SEND, feeShannons: "9", settledAtMs: NOW });
            expect(isStoredPaymentRecord(settled)).toBe(true);
            expect(FAILED_SEND.failedReason).toBe("no path found");
        });

        it.each([
            ["a failed send that fails again", FAILED_SEND, { status: "failed", reason: "another reason" }],
            ["a failed receive that fails again", FAILED_RECEIVE, { status: "failed", reason: "another reason" }],
            ["a failed receive that completes", FAILED_RECEIVE, { status: "completed", feeShannons: "0" }],
            ["a completed send that completes again", COMPLETED_SEND, { status: "completed", feeShannons: "9" }],
            ["a completed send that fails", COMPLETED_SEND, { status: "failed", reason: "no path found" }],
            ["a completed receive that completes again", COMPLETED_RECEIVE, { status: "completed", feeShannons: "0" }],
            ["a completed receive that fails", COMPLETED_RECEIVE, { status: "failed", reason: "the invoice expired" }],
        ] as const)("hands back %s as the very same object", (_, current, outcome) => {
            expect(settlePaymentRecord(current, outcome, NOW)).toBe(current);
        });
    });

    describe("toSdkPaymentRecord", () => {
        it("strips the version, as a copy", () => {
            const record = toSdkPaymentRecord(COMPLETED_SEND);
            expect(record).toStrictEqual({
                paymentHashHex: `0x${HASH}`,
                direction: "send",
                status: "completed",
                amountShannons: "100000",
                invoice: INVOICE,
                description: "coffee",
                maxFeeShannons: "500",
                feeShannons: "7",
                failedReason: null,
                createdAtMs: 1700000000000,
                settledAtMs: 1700000005000,
            });
            expect(record).not.toBe(COMPLETED_SEND);
        });

        it("drops the fields a stored record carries beyond its shape", () => {
            const stored = { ...FAILED_RECEIVE, extra: "dropped" };
            expect(toSdkPaymentRecord(stored)).toStrictEqual({
                paymentHashHex: `0x${HASH_1}`,
                direction: "receive",
                status: "failed",
                amountShannons: "200000",
                invoice: RECEIVE_INVOICE,
                description: null,
                maxFeeShannons: null,
                feeShannons: null,
                failedReason: "the invoice expired",
                createdAtMs: 1700000010000,
                settledAtMs: 1700000090000,
            });
        });
    });
});
