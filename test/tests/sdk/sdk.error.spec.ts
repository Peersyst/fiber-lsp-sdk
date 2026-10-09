import { SDK_ERROR_CODES, SdkError } from "../../../src/sdk";
import { SessionError } from "../../../src/session";

describe("SdkError", () => {
    it("carries its code, its message and its name", () => {
        const error = new SdkError("connect_failed", "the signer session could not be established");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("SdkError");
        expect(error.code).toBe("connect_failed");
        expect(error.message).toBe("the signer session could not be established");
        expect(error.cause).toBeUndefined();
    });

    it("carries the module's error underneath as its cause", () => {
        const cause = new SessionError("handshake_refused", "the bridge closed the socket during authentication");
        const error = new SdkError("connect_failed", "the signer session could not be established", { cause });
        expect(error.cause).toBe(cause);
    });

    it("takes any of the codes", () => {
        for (const code of SDK_ERROR_CODES) expect(new SdkError(code, code).code).toBe(code);
    });

    it("pins the codes", () => {
        expect(SDK_ERROR_CODES).toEqual(["connect_failed", "session_error", "poll_failed", "clock_before_floor"]);
    });
});
