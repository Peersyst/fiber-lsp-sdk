import type { ChannelPolicyRecord } from "../../../../src/policy";
import {
    assertChannelPolicyRecord,
    assertDebitIntentRecord,
    assertHoldInvoicePolicyRecord,
} from "../../../../src/policy/utils/assert.utils";

function record(): ChannelPolicyRecord {
    return {
        version: 1,
        channelId: "0x1f".padEnd(66, "a"),
        lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
        signedSessions: { "COMMITMENT:5": "ab".repeat(32) },
        lastStateVersion: 7,
        views: {
            remote: { exposureShannons: "5000000000", tlcs: [], chargedShannons: {}, creditedShannons: {} },
            local: { exposureShannons: "5000000000", tlcs: [], chargedShannons: {}, creditedShannons: {} },
        },
    };
}

describe("assertChannelPolicyRecord", () => {
    it("accepts a valid record", () => {
        expect(() => assertChannelPolicyRecord("record", record())).not.toThrow();
    });

    it.each(["record", "updated record"])("names the value %p in the refusal", (name) => {
        expect(() => assertChannelPolicyRecord(name, { ...record(), version: 2 })).toThrow(
            new TypeError(`${name} is not a valid channel policy record`),
        );
    });

    it.each([null, undefined, "record", 42])("rejects the non-object %p", (value) => {
        expect(() => assertChannelPolicyRecord("record", value)).toThrow(TypeError);
    });
});

describe("assertDebitIntentRecord", () => {
    it("accepts a valid record", () => {
        expect(() =>
            assertDebitIntentRecord("record", {
                version: 1,
                paymentHash: "11".repeat(32),
                maxShannons: "1",
                open: false,
                channelIndexes: [],
            }),
        ).not.toThrow();
    });

    it("names the value in the refusal", () => {
        expect(() => assertDebitIntentRecord("updated record", { paymentHash: "11".repeat(32) })).toThrow(
            new TypeError("updated record is not a valid debit intent record"),
        );
    });
});

describe("assertHoldInvoicePolicyRecord", () => {
    it("accepts a valid record", () => {
        expect(() =>
            assertHoldInvoicePolicyRecord("record", {
                version: 1,
                paymentHash: "11".repeat(32),
                amountShannons: "1",
                hashAlgorithm: "ckb-hash",
                released: true,
                channelIndexes: [0],
            }),
        ).not.toThrow();
    });

    it("names the value in the refusal", () => {
        expect(() => assertHoldInvoicePolicyRecord("updated record", { paymentHash: "11".repeat(32) })).toThrow(
            new TypeError("updated record is not a valid hold invoice record"),
        );
    });
});
