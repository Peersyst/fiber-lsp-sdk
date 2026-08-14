import type { ChannelPolicyRecord } from "../../../../src/policy";
import { isChannelPolicyRecord } from "../../../../src/policy/utils/validate.utils";

const MAX_COMMITMENT_NUMBER = 2 ** 48 - 1;

describe("isChannelPolicyRecord", () => {
    function record(): ChannelPolicyRecord {
        return {
            version: 1,
            channelId: "0x1f".padEnd(66, "a"),
            lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
            signedSessions: { "COMMITMENT:5": "ab".repeat(32) },
            lastStateVersion: 7,
            localExposureShannons: "5000000000",
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
                signedSessions: {},
                pendingDebitsShannons: [],
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
        ["a balance with a leading zero", { localExposureShannons: "01" }],
        ["a negative balance", { localExposureShannons: "-1" }],
        ["a numeric balance", { localExposureShannons: 100 }],
        ["debits that are not an array", { pendingDebitsShannons: "100" }],
        ["a debit that is not decimal", { pendingDebitsShannons: ["100", "1.5"] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isChannelPolicyRecord({ ...record(), ...override })).toBe(false);
    });
});
