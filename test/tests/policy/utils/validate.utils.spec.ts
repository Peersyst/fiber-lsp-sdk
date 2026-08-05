import type { ChannelPolicyRecord } from "../../../../src/policy";
import { assertChannelPolicyRecord, isChannelPolicyRecord, isDecimalShannons } from "../../../../src/policy/utils";

const MAX_COMMITMENT_NUMBER = 2 ** 48 - 1;

describe("isDecimalShannons", () => {
    it.each(["0", "1", "10", "5000000000", "340282366920938463463374607431768211455"])("accepts %s", (value) => {
        expect(isDecimalShannons(value)).toBe(true);
    });

    it.each(["", "01", "-1", "+1", "1.5", "1e3", " 1", "1 ", "0x10", "١٢٣"])("rejects %p", (value) => {
        expect(isDecimalShannons(value)).toBe(false);
    });

    it("rejects amounts beyond u128", () => {
        expect(isDecimalShannons("340282366920938463463374607431768211455")).toBe(true);
        expect(isDecimalShannons("340282366920938463463374607431768211456")).toBe(false);
        expect(isDecimalShannons("1" + "0".repeat(39))).toBe(false);
        expect(isDecimalShannons("9".repeat(1000))).toBe(false);
    });

    it.each([5, 5n, null, undefined])("rejects the non-string %p", (value) => {
        expect(isDecimalShannons(value)).toBe(false);
    });
});

describe("isChannelPolicyRecord", () => {
    function record(): ChannelPolicyRecord {
        return {
            version: 1,
            channelIndex: 3,
            lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
            signedDigests: { "COMMITMENT:5": "ab".repeat(32) },
            lastStateVersion: 7,
            localBalanceShannons: "5000000000",
            pendingDebitsShannons: ["100", "0"],
        };
    }

    it("accepts a valid record", () => {
        expect(isChannelPolicyRecord(record())).toBe(true);
    });

    it("accepts the empty maps of a freshly registered channel", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                lastSignedCommitmentNumbers: {},
                signedDigests: {},
                pendingDebitsShannons: [],
            }),
        ).toBe(true);
    });

    it("accepts the boundary commitment number", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                lastSignedCommitmentNumbers: { COMMITMENT: MAX_COMMITMENT_NUMBER },
                signedDigests: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER}`]: "ab".repeat(32) },
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

        const inDigests = { ...record(), signedDigests: JSON.parse('{"__proto__":"' + "ab".repeat(32) + '"}') as unknown };
        expect(isChannelPolicyRecord(inDigests)).toBe(false);
    });

    it.each([null, undefined, [], "record", 42])("rejects the non-object %p", (value) => {
        expect(isChannelPolicyRecord(value)).toBe(false);
    });

    it.each([
        ["a missing version", { version: undefined }],
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["a negative channel index", { channelIndex: -1 }],
        ["a fractional channel index", { channelIndex: 1.5 }],
        ["a string channel index", { channelIndex: "3" }],
        ["counters that are not an object", { lastSignedCommitmentNumbers: [] }],
        ["a counter for an unknown context", { lastSignedCommitmentNumbers: { SETTLEMENT: 1 } }],
        ["a counter above the commitment cap", { lastSignedCommitmentNumbers: { COMMITMENT: MAX_COMMITMENT_NUMBER + 1 } }],
        ["a negative counter", { lastSignedCommitmentNumbers: { COMMITMENT: -1 } }],
        ["digests that are not an object", { signedDigests: [] }],
        ["a slot without a number", { signedDigests: { COMMITMENT: "ab".repeat(32) } }],
        ["a slot with an unknown context", { signedDigests: { "SETTLEMENT:1": "ab".repeat(32) } }],
        ["a slot with a non-canonical number", { signedDigests: { "COMMITMENT:01": "ab".repeat(32) } }],
        ["a slot above the commitment cap", { signedDigests: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER + 1}`]: "ab".repeat(32) } }],
        ["a digest that is not 32 bytes", { signedDigests: { "COMMITMENT:5": "ab".repeat(31) } }],
        ["an uppercase digest", { signedDigests: { "COMMITMENT:5": "AB".repeat(32) } }],
        ["a negative state version", { lastStateVersion: -1 }],
        ["a fractional state version", { lastStateVersion: 0.5 }],
        ["a balance with a leading zero", { localBalanceShannons: "01" }],
        ["a negative balance", { localBalanceShannons: "-1" }],
        ["a numeric balance", { localBalanceShannons: 100 }],
        ["debits that are not an array", { pendingDebitsShannons: "100" }],
        ["a debit that is not decimal", { pendingDebitsShannons: ["100", "1.5"] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isChannelPolicyRecord({ ...record(), ...override })).toBe(false);
    });

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
});
