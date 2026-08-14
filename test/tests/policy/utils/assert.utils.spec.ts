import type { ChannelPolicyRecord } from "../../../../src/policy";
import { assertChannelPolicyRecord } from "../../../../src/policy/utils/assert.utils";

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
