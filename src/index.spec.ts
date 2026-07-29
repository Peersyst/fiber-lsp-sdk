import { DERIVATION_SCHEME_VERSION, PROTOCOL_VERSION, SIGNER_ERROR_CODES } from "./index.js";

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
});
