import type { ChannelPolicyRecord, ChannelWatermark } from "../../../../src/policy";
import { buildChannelRecord, projectChannelWatermark } from "../../../../src/policy/utils";

const RECORD: ChannelPolicyRecord = {
    version: 1,
    channelId: "0x1f".padEnd(66, "a"),
    lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4, ANNOUNCEMENT: 0 },
    signedSessions: {
        "COMMITMENT:2": "aa".repeat(32),
        "COMMITMENT:5": "bb".repeat(32),
        "REVOKE:4": "cc".repeat(32),
        "ANNOUNCEMENT:0": "dd".repeat(32),
    },
    lastStateVersion: 7,
    localExposureShannons: "62000000000",
    pendingDebitsShannons: ["100", "200"],
};

describe("projecting a record onto its watermark", () => {
    it("keeps the counters, the exposure and the state version", () => {
        const watermark = projectChannelWatermark(RECORD);
        expect(watermark.version).toBe(1);
        expect(watermark.lastSignedCommitmentNumbers).toEqual({ COMMITMENT: 5, REVOKE: 4, ANNOUNCEMENT: 0 });
        expect(watermark.lastStateVersion).toBe(7);
        expect(watermark.localExposureShannons).toBe("62000000000");
    });

    it("prunes the registry to the top slot of each context", () => {
        expect(projectChannelWatermark(RECORD).signedSessions).toEqual({
            "COMMITMENT:5": "bb".repeat(32),
            "REVOKE:4": "cc".repeat(32),
            "ANNOUNCEMENT:0": "dd".repeat(32),
        });
    });

    it("keeps a counter whose slot the registry no longer holds", () => {
        const watermark = projectChannelWatermark({ ...RECORD, signedSessions: {} });
        expect(watermark.lastSignedCommitmentNumbers).toEqual({ COMMITMENT: 5, REVOKE: 4, ANNOUNCEMENT: 0 });
        expect(watermark.signedSessions).toEqual({});
    });

    it("copies the counters, so a later claim on the record cannot reach into the watermark", () => {
        const record = { ...RECORD, lastSignedCommitmentNumbers: { COMMITMENT: 5 } };
        const watermark = projectChannelWatermark(record);
        record.lastSignedCommitmentNumbers.COMMITMENT = 6;
        expect(watermark.lastSignedCommitmentNumbers).toEqual({ COMMITMENT: 5 });
    });
});

describe("building the record a channel starts from", () => {
    it("starts a channel the device never signed for at the exposure it was given", () => {
        expect(buildChannelRecord("0x2f", null, "1000")).toEqual<ChannelPolicyRecord>({
            version: 1,
            channelId: "0x2f",
            lastSignedCommitmentNumbers: {},
            signedSessions: {},
            lastStateVersion: 0,
            localExposureShannons: "1000",
            pendingDebitsShannons: [],
        });
    });

    it("expands a watermark, taking its exposure over the one it was given", () => {
        const watermark: ChannelWatermark = {
            version: 1,
            lastSignedCommitmentNumbers: { COMMITMENT: 5 },
            signedSessions: { "COMMITMENT:5": "bb".repeat(32) },
            lastStateVersion: 7,
            localExposureShannons: "62000000000",
        };
        expect(buildChannelRecord("0x2f", watermark, "1000")).toEqual<ChannelPolicyRecord>({
            version: 1,
            channelId: "0x2f",
            lastSignedCommitmentNumbers: { COMMITMENT: 5 },
            signedSessions: { "COMMITMENT:5": "bb".repeat(32) },
            lastStateVersion: 7,
            localExposureShannons: "62000000000",
            pendingDebitsShannons: [],
        });
    });

    it("never brings back a debit intent, which the user authorised on a device that is gone", () => {
        const watermark = projectChannelWatermark(RECORD);
        expect(buildChannelRecord("0x2f", watermark, "1000").pendingDebitsShannons).toEqual([]);
    });
});
