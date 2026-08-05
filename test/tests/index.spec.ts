import * as sdk from "../../src";
import { DERIVATION_SCHEME_VERSION, PROTOCOL_VERSION, SIGNER_ERROR_CODES } from "../../src";

describe("public entrypoint", () => {
    it("exposes protocol version 1", () => {
        expect(PROTOCOL_VERSION).toBe(1);
    });

    it("exposes derivation scheme version 1", () => {
        expect(DERIVATION_SCHEME_VERSION).toBe(1);
    });

    it("exposes the four signer error codes", () => {
        expect(SIGNER_ERROR_CODES).toEqual(["unknown_channel", "malformed", "stale_state", "policy_refusal"]);
    });

    // No API may return a private key: anything added here is a published commitment.
    it("publishes nothing beyond the declared surface", () => {
        expect(Object.keys(sdk).sort()).toEqual(
            [
                "BIP39_SEED_LENGTH",
                "DERIVATION_SCHEME_VERSION",
                "MAX_ACCOUNT_INDEX",
                "PROTOCOL_VERSION",
                "SIGNER_ERROR_CODES",
                "deriveMasterSeed",
            ].sort(),
        );
    });
});
