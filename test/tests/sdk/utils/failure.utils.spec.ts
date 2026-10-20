import { RpcError } from "../../../../src/rpc";
import { describeSdkFailure } from "../../../../src/sdk";

describe("describeSdkFailure", () => {
    it("appends the message of any other error", () => {
        expect(describeSdkFailure("a poll of the node failed", new RpcError("list_channels", -32000, "node is syncing"))).toBe(
            "a poll of the node failed: node is syncing",
        );
        expect(describeSdkFailure("a poll of the node failed", new Error("socket error"))).toBe("a poll of the node failed: socket error");
    });

    it.each([undefined, null, "boom", 7, { message: "not an error" }])("says only what failed when the cause is %p", (cause) => {
        expect(describeSdkFailure("a poll of the node failed", cause)).toBe("a poll of the node failed");
    });
});
