import { BridgeError, SessionError } from "../../../src/session";

describe("SessionError", () => {
    it("carries its kind and message and is an Error", () => {
        const error = new SessionError("version_mismatch", "the bridge speaks protocol version 2, this device speaks 1");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("SessionError");
        expect(error.kind).toBe("version_mismatch");
        expect(error.message).toBe("the bridge speaks protocol version 2, this device speaks 1");
        expect(error.cause).toBeUndefined();
    });

    it("keeps the cause it is given", () => {
        const cause = new Error("enclave busy");
        expect(new SessionError("authentication_failed", "the authenticator could not sign the challenge", { cause }).cause).toBe(cause);
    });
});

describe("BridgeError", () => {
    it("carries the bridge's code and message and is an Error", () => {
        const error = new BridgeError("duplicate_keys", "a channel with these keys exists");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("BridgeError");
        expect(error.code).toBe("duplicate_keys");
        expect(error.message).toBe("a channel with these keys exists");
    });

    it("is not a SessionError, so a refusal by the bridge is told apart from the session's own failures", () => {
        expect(new BridgeError("x", "y")).not.toBeInstanceOf(SessionError);
    });
});
