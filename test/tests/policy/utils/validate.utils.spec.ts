import type { ChannelPolicyRecord, DebitIntentRecord, HoldInvoicePolicyRecord, PolicyViewSnapshot } from "../../../../src/policy";
import { isChannelPolicyRecord, isDebitIntentRecord, isHoldInvoicePolicyRecord } from "../../../../src/policy/utils/validate.utils";

const MAX_COMMITMENT_NUMBER = 2 ** 48 - 1;

describe("isChannelPolicyRecord", () => {
    function record(): ChannelPolicyRecord {
        return {
            version: 1,
            channelId: "0x1f".padEnd(66, "a"),
            lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
            signedSessions: { "COMMITMENT:5": "ab".repeat(32) },
            lastStateVersion: 7,
            views: { remote: snapshot(), local: snapshot() },
        };
    }

    function snapshot(): PolicyViewSnapshot {
        return {
            exposureShannons: "5000000000",
            tlcs: [
                {
                    direction: "offered",
                    hashAlgorithm: "ckb-hash",
                    boundPaymentHash: "33".repeat(20),
                    amountShannons: "100",
                    expirySeconds: "1700000000",
                },
            ],
            chargedShannons: { ["44".repeat(20)]: "7" },
            creditedShannons: { ["55".repeat(20)]: "0" },
        };
    }

    function withRemote(override: Record<string, unknown>): Record<string, unknown> {
        return { ...record(), views: { remote: { ...snapshot(), ...override }, local: snapshot() } };
    }

    function withTlc(override: Record<string, unknown>): Record<string, unknown> {
        return withRemote({ tlcs: [{ ...snapshot().tlcs[0], ...override }] });
    }

    it("accepts a valid record", () => {
        expect(isChannelPolicyRecord(record())).toBe(true);
    });

    it("accepts the empty maps of a freshly registered channel", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                lastSignedCommitmentNumbers: {},
                signedSessions: {},
                views: {
                    remote: { exposureShannons: "0", tlcs: [], chargedShannons: {}, creditedShannons: {} },
                    local: { exposureShannons: "0", tlcs: [], chargedShannons: {}, creditedShannons: {} },
                },
            }),
        ).toBe(true);
    });

    it("accepts the boundary commitment number", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                lastSignedCommitmentNumbers: { COMMITMENT: MAX_COMMITMENT_NUMBER },
                signedSessions: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER}`]: "ab".repeat(32) },
            }),
        ).toBe(true);
    });

    it("tolerates unknown extra fields", () => {
        expect(isChannelPolicyRecord({ ...record(), futureField: "x" })).toBe(true);
    });

    it.each(Object.keys(record()))("rejects a record missing %s", (field) => {
        const value = record() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isChannelPolicyRecord(value)).toBe(false);
    });

    // JSON.parse creates __proto__ as an own property; it must neither pollute nor pass as a slot key.
    it("handles __proto__ keys without prototype pollution", () => {
        const withExtra = JSON.parse(`{"__proto__":{"polluted":true},${JSON.stringify(record()).slice(1)}`) as unknown;
        expect(isChannelPolicyRecord(withExtra)).toBe(true);
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();

        const inDigests = { ...record(), signedSessions: JSON.parse('{"__proto__":"' + "ab".repeat(32) + '"}') as unknown };
        expect(isChannelPolicyRecord(inDigests)).toBe(false);
    });

    it.each([null, undefined, [], "record", 42])("rejects the non-object %p", (value) => {
        expect(isChannelPolicyRecord(value)).toBe(false);
    });

    it.each([
        ["a missing version", { version: undefined }],
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["an empty channel id", { channelId: "" }],
        ["a numeric channel id", { channelId: 3 }],
        ["counters that are not an object", { lastSignedCommitmentNumbers: [] }],
        ["a counter for an unknown context", { lastSignedCommitmentNumbers: { SETTLEMENT: 1 } }],
        ["a counter above the commitment cap", { lastSignedCommitmentNumbers: { COMMITMENT: MAX_COMMITMENT_NUMBER + 1 } }],
        ["a negative counter", { lastSignedCommitmentNumbers: { COMMITMENT: -1 } }],
        ["digests that are not an object", { signedSessions: [] }],
        ["a slot without a number", { signedSessions: { COMMITMENT: "ab".repeat(32) } }],
        ["a slot with an unknown context", { signedSessions: { "SETTLEMENT:1": "ab".repeat(32) } }],
        ["a slot with a non-canonical number", { signedSessions: { "COMMITMENT:01": "ab".repeat(32) } }],
        ["a slot above the commitment cap", { signedSessions: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER + 1}`]: "ab".repeat(32) } }],
        ["a digest that is not 32 bytes", { signedSessions: { "COMMITMENT:5": "ab".repeat(31) } }],
        ["an uppercase digest", { signedSessions: { "COMMITMENT:5": "AB".repeat(32) } }],
        ["a negative state version", { lastStateVersion: -1 }],
        ["a fractional state version", { lastStateVersion: 0.5 }],
        ["views that are not an object", { views: [] }],
        ["one view only", { views: { remote: snapshot() } }],
        ["a view that is not an object", { views: { remote: snapshot(), local: "snapshot" } }],
    ])("rejects a record with %s", (_, override) => {
        expect(isChannelPolicyRecord({ ...record(), ...override })).toBe(false);
    });

    it("tolerates an unknown extra key beside the two views", () => {
        expect(isChannelPolicyRecord({ ...record(), views: { remote: snapshot(), local: snapshot(), futureView: "x" } })).toBe(true);
    });

    it.each(Object.keys(snapshot()))("rejects a view missing %s", (field) => {
        const view = snapshot() as unknown as Record<string, unknown>;
        delete view[field];
        expect(isChannelPolicyRecord({ ...record(), views: { remote: snapshot(), local: view } })).toBe(false);
    });

    it.each([
        ["an exposure with a leading zero", { exposureShannons: "01" }],
        ["a negative exposure", { exposureShannons: "-1" }],
        ["a numeric exposure", { exposureShannons: 100 }],
        ["an exposure above u128", { exposureShannons: "340282366920938463463374607431768211456" }],
        ["TLCs that are not an array", { tlcs: {} }],
        ["a TLC that is not an object", { tlcs: ["tlc"] }],
        ["charges that are not an object", { chargedShannons: [] }],
        ["a charge under a full 32-byte hash", { chargedShannons: { ["44".repeat(32)]: "7" } }],
        ["a charge under an uppercase hash", { chargedShannons: { ["AB".repeat(20)]: "7" } }],
        ["a charge that is not decimal", { chargedShannons: { ["44".repeat(20)]: "0x7" } }],
        ["credits that are not an object", { creditedShannons: "none" }],
        ["a credit under a short hash", { creditedShannons: { ["55".repeat(19)]: "0" } }],
        ["a credit that is negative", { creditedShannons: { ["55".repeat(20)]: "-1" } }],
    ])("rejects a view with %s", (_, override) => {
        expect(isChannelPolicyRecord(withRemote(override))).toBe(false);
    });

    it.each(["direction", "hashAlgorithm", "boundPaymentHash", "amountShannons", "expirySeconds"])("rejects a TLC missing %s", (field) => {
        const tlc: Record<string, unknown> = { ...snapshot().tlcs[0] };
        delete tlc[field];
        expect(isChannelPolicyRecord(withRemote({ tlcs: [tlc] }))).toBe(false);
    });

    it.each([
        ["an unknown direction", { direction: "forwarded" }],
        ["an algorithm fiber does not define", { hashAlgorithm: "ckb_hash" }],
        ["a full 32-byte hash", { boundPaymentHash: "33".repeat(32) }],
        ["an uppercase hash", { boundPaymentHash: "AB".repeat(20) }],
        ["an amount that is not decimal", { amountShannons: "1e3" }],
        ["a numeric expiry", { expirySeconds: 1700000000 }],
        ["an expiry with a leading zero", { expirySeconds: "01" }],
        ["a negative expiry", { expirySeconds: "-1" }],
        ["an expiry above u64", { expirySeconds: "18446744073709551616" }],
        ["an expiry of more digits than u64 has", { expirySeconds: "1".repeat(21) }],
    ])("rejects a TLC with %s", (_, override) => {
        expect(isChannelPolicyRecord(withTlc(override))).toBe(false);
    });

    it("accepts a TLC expiring at the last second u64 can hold", () => {
        expect(isChannelPolicyRecord(withTlc({ expirySeconds: "18446744073709551615" }))).toBe(true);
    });
});

describe("isDebitIntentRecord", () => {
    function intent(): DebitIntentRecord {
        return { version: 1, paymentHash: "11".repeat(32), maxShannons: "1500000000", open: true, channelIndexes: [3, 0] };
    }

    it("accepts a valid record, and one no channel has shown yet", () => {
        expect(isDebitIntentRecord(intent())).toBe(true);
        expect(isDebitIntentRecord({ ...intent(), channelIndexes: [] })).toBe(true);
    });

    it("tolerates unknown extra fields", () => {
        expect(isDebitIntentRecord({ ...intent(), futureField: "x" })).toBe(true);
    });

    it.each(Object.keys(intent()))("rejects a record missing %s", (field) => {
        const value = intent() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isDebitIntentRecord(value)).toBe(false);
    });

    it.each([null, [], "intent"])("rejects the non-object %p", (value) => {
        expect(isDebitIntentRecord(value)).toBe(false);
    });

    it.each([
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["a truncated hash", { paymentHash: "11".repeat(20) }],
        ["an uppercase hash", { paymentHash: "AB".repeat(32) }],
        ["a maximum that is not decimal", { maxShannons: "0x10" }],
        ["a string flag", { open: "true" }],
        ["channels that are not an array", { channelIndexes: 3 }],
        ["a negative channel index", { channelIndexes: [-1] }],
        ["a repeated channel index", { channelIndexes: [3, 3] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isDebitIntentRecord({ ...intent(), ...override })).toBe(false);
    });
});

describe("isHoldInvoicePolicyRecord", () => {
    function invoice(): HoldInvoicePolicyRecord {
        return {
            version: 1,
            paymentHash: "11".repeat(32),
            amountShannons: "2250000000",
            hashAlgorithm: "ckb-hash",
            released: false,
            channelIndexes: [7],
        };
    }

    it("accepts a valid record", () => {
        expect(isHoldInvoicePolicyRecord(invoice())).toBe(true);
    });

    it("tolerates unknown extra fields", () => {
        expect(isHoldInvoicePolicyRecord({ ...invoice(), futureField: "x" })).toBe(true);
    });

    it.each(Object.keys(invoice()))("rejects a record missing %s", (field) => {
        const value = invoice() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isHoldInvoicePolicyRecord(value)).toBe(false);
    });

    it.each([null, [], "invoice"])("rejects the non-object %p", (value) => {
        expect(isHoldInvoicePolicyRecord(value)).toBe(false);
    });

    it.each([
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["a truncated hash", { paymentHash: "11".repeat(20) }],
        ["an amount that is not decimal", { amountShannons: "-5" }],
        ["a numeric flag", { released: 0 }],
        ["a fractional channel index", { channelIndexes: [1.5] }],
        ["a repeated channel index", { channelIndexes: [7, 7] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isHoldInvoicePolicyRecord({ ...invoice(), ...override })).toBe(false);
    });
});
