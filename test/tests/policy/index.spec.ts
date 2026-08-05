import * as policy from "../../../src/policy";

describe("policy module surface", () => {
    it("exports the persistence surface the rest of the SDK consumes", () => {
        expect(Object.keys(policy).sort()).toEqual(
            [
                "CHANNEL_POLICY_RECORD_VERSION",
                "CHANNEL_RECORD_KEY_PREFIX",
                "HOLD_INVOICE_PREIMAGE_KEY_PREFIX",
                "MAX_AMOUNT_SHANNONS",
                "MESSAGE_DIGEST_LENGTH",
                "PAYMENT_HASH_LENGTH",
                "PREIMAGE_LENGTH",
                "STORAGE_KEY_NAMESPACE",
                "SignerStore",
            ].sort(),
        );
    });

    it("keeps the record version at 1", () => {
        expect(policy.CHANNEL_POLICY_RECORD_VERSION).toBe(1);
    });
});
