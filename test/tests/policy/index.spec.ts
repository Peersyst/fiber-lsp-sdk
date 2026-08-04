import * as policy from "../../../src/policy/index.js";

describe("policy module surface", () => {
    it("exports the persistence surface the rest of the SDK consumes", () => {
        expect(Object.keys(policy).sort()).toEqual(["CHANNEL_POLICY_RECORD_VERSION", "SignerStore"].sort());
    });

    it("keeps the record version at 1", () => {
        expect(policy.CHANNEL_POLICY_RECORD_VERSION).toBe(1);
    });
});
