import { RPC_CHANNEL_STATE_NAMES, RPC_INVOICE_STATUSES, RPC_PAYMENT_STATUSES } from "../../../../src/rpc";
import type { ActivityRecord } from "../../../../src/sdk";
import {
    ACTIVITY_KINDS,
    ACTIVITY_RECORD_VERSION,
    activityField,
    assertActivityId,
    assertActivityRecord,
    assertActivityStatus,
    emptyActivityRecord,
    isActivityId,
    isActivityRecord,
    isActivityStatus,
} from "../../../../src/sdk";

const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const HASH = "ab".repeat(32);
const RECORD: ActivityRecord = {
    version: 1,
    channels: { [CHANNEL_ID]: { status: null }, [`0x${"2e".repeat(32)}`]: { status: "ChannelReady" } },
    payments: { [HASH]: { status: "Inflight" } },
    invoices: { ["cd".repeat(32)]: { status: "Received" }, ["ef".repeat(32)]: { status: null } },
};

describe("activity record", () => {
    it("pins the kinds, their fields and the version", () => {
        expect(ACTIVITY_KINDS).toEqual(["channel", "payment", "invoice"]);
        expect(ACTIVITY_KINDS.map(activityField)).toEqual(["channels", "payments", "invoices"]);
        expect(ACTIVITY_RECORD_VERSION).toBe(1);
    });

    it("builds an empty record that watches nothing, a new object each time", () => {
        expect(emptyActivityRecord()).toEqual({ version: 1, channels: {}, payments: {}, invoices: {} });
        expect(emptyActivityRecord()).not.toBe(emptyActivityRecord());
    });

    describe("ids", () => {
        it("takes a channel id in the one form the node's listing is read in", () => {
            expect(isActivityId("channel", CHANNEL_ID)).toBe(true);
            expect(() => assertActivityId("channel", CHANNEL_ID)).not.toThrow();
        });

        it.each(["payment", "invoice"] as const)("takes the 32-byte payment hash in lowercase hex as a %s id", (kind) => {
            expect(isActivityId(kind, HASH)).toBe(true);
            expect(() => assertActivityId(kind, HASH)).not.toThrow();
        });

        it.each([
            ["channel", "", "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", 7, "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", undefined, "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", "temporary-name", "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", CHANNEL_ID.slice(2), "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", CHANNEL_ID.toUpperCase().replace("0X", "0x"), "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", `${CHANNEL_ID}00`, "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["channel", "0x", "channel id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["payment", "", "payment id must be 32 bytes of lowercase hex"],
            ["payment", `0x${HASH}`, "payment id must be 32 bytes of lowercase hex"],
            ["payment", HASH.toUpperCase(), "payment id must be 32 bytes of lowercase hex"],
            ["payment", HASH.slice(2), "payment id must be 32 bytes of lowercase hex"],
            ["invoice", `${HASH}00`, "invoice id must be 32 bytes of lowercase hex"],
            ["invoice", null, "invoice id must be 32 bytes of lowercase hex"],
        ] as const)("refuses, as a %s id, %p", (kind, id, message) => {
            expect(isActivityId(kind, id)).toBe(false);
            expect(() => assertActivityId(kind, id)).toThrow(new TypeError(message));
        });
    });

    describe("statuses", () => {
        it("takes fiber's channel states, payment statuses and invoice statuses, each for its kind only", () => {
            for (const status of RPC_CHANNEL_STATE_NAMES) expect(isActivityStatus("channel", status)).toBe(true);
            for (const status of RPC_PAYMENT_STATUSES) expect(isActivityStatus("payment", status)).toBe(true);
            for (const status of RPC_INVOICE_STATUSES) expect(isActivityStatus("invoice", status)).toBe(true);
            expect(isActivityStatus("channel", "Paid")).toBe(false);
            expect(isActivityStatus("payment", "ChannelReady")).toBe(false);
            expect(isActivityStatus("invoice", "Success")).toBe(false);
        });

        it.each([
            ["channel", "closed", "channel status must be one of " + RPC_CHANNEL_STATE_NAMES.join(", ")],
            ["payment", null, "payment status must be one of Created, Inflight, Success, Failed"],
            ["invoice", 1, "invoice status must be one of Open, Cancelled, Expired, Received, Paid"],
        ] as const)("refuses, as a %s status, %p", (kind, status, message) => {
            expect(() => assertActivityStatus(kind, status)).toThrow(new TypeError(message));
        });
    });

    describe("the record", () => {
        it("accepts a record with entries of every kind and status, and the empty one", () => {
            expect(isActivityRecord(RECORD)).toBe(true);
            expect(() => assertActivityRecord("record", RECORD)).not.toThrow();
            expect(isActivityRecord(emptyActivityRecord())).toBe(true);
        });

        it("tolerates unknown extra fields, on the record and on an entry", () => {
            expect(isActivityRecord({ ...RECORD, extra: 1 })).toBe(true);
            expect(isActivityRecord({ ...RECORD, payments: { [HASH]: { status: "Inflight", since: 5 } } })).toBe(true);
        });

        it.each([
            ["null", null],
            ["an array", []],
            ["a string", JSON.stringify(RECORD)],
            ["no version", { channels: {}, payments: {}, invoices: {} }],
            ["a version from the future", { ...RECORD, version: 2 }],
            ["a version as a string", { ...RECORD, version: "1" }],
            ["no channels", { version: 1, payments: {}, invoices: {} }],
            ["no payments", { version: 1, channels: {}, invoices: {} }],
            ["no invoices", { version: 1, channels: {}, payments: {} }],
            ["channels as an array", { ...RECORD, channels: [] }],
            ["payments as null", { ...RECORD, payments: null }],
            ["a channel entry that is not an object", { ...RECORD, channels: { [CHANNEL_ID]: "ChannelReady" } }],
            ["a channel entry that is null", { ...RECORD, channels: { [CHANNEL_ID]: null } }],
            ["a channel entry without a status", { ...RECORD, channels: { [CHANNEL_ID]: {} } }],
            ["an empty channel id", { ...RECORD, channels: { "": { status: null } } }],
            ["a channel id without its prefix", { ...RECORD, channels: { [CHANNEL_ID.slice(2)]: { status: null } } }],
            ["a channel status of another kind", { ...RECORD, channels: { [CHANNEL_ID]: { status: "Paid" } } }],
            ["a payment id that is not a hash", { ...RECORD, payments: { payment: { status: null } } }],
            ["a payment status of another kind", { ...RECORD, payments: { [HASH]: { status: "Open" } } }],
            ["an invoice status of another kind", { ...RECORD, invoices: { [HASH]: { status: "Failed" } } }],
            ["an invoice status that is undefined", { ...RECORD, invoices: { [HASH]: { status: undefined } } }],
        ])("refuses %s", (_, value) => {
            expect(isActivityRecord(value)).toBe(false);
            expect(() => assertActivityRecord("record", value)).toThrow(new TypeError("record is not a valid activity record"));
        });
    });
});
