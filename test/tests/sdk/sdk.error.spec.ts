import { SDK_ERROR_CODES, SdkError } from "../../../src/sdk";
import { RpcError } from "../../../src/rpc";

describe("SdkError", () => {
    it("carries its code, its message and its name", () => {
        const error = new SdkError("poll_failed", "the node could not be read");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("SdkError");
        expect(error.code).toBe("poll_failed");
        expect(error.message).toBe("the node could not be read");
        expect(error.cause).toBeUndefined();
    });

    it("carries the module's error underneath as its cause", () => {
        const cause = new RpcError("list_channels", -32000, "node is syncing");
        const error = new SdkError("poll_failed", "the node could not be read", { cause });
        expect(error.cause).toBe(cause);
    });

    it("takes any of the codes", () => {
        for (const code of SDK_ERROR_CODES) expect(new SdkError(code, code).code).toBe(code);
    });

    it("pins the codes", () => {
        expect(SDK_ERROR_CODES).toEqual(["poll_failed", "clock_before_floor"]);
    });
});
