import { RpcError } from "../../../../src/rpc";
import { describeSdkFailure } from "../../../../src/sdk";
import { SessionError } from "../../../../src/session";

describe("describeSdkFailure", () => {
    it("names the kind of a session error before its message", () => {
        const cause = new SessionError("handshake_refused", "the bridge closed the socket during authentication");
        expect(describeSdkFailure("the signer session could not be established", cause)).toBe(
            "the signer session could not be established (handshake_refused): the bridge closed the socket during authentication",
        );
    });

    it("appends the message of any other error", () => {
        expect(describeSdkFailure("a poll of the node failed", new RpcError("list_channels", -32000, "node is syncing"))).toBe(
            "a poll of the node failed: node is syncing",
        );
        expect(describeSdkFailure("a poll of the node failed", new Error("socket error"))).toBe("a poll of the node failed: socket error");
    });

    it.each([undefined, null, "boom", 7, { message: "not an error" }])("says only what failed when the cause is %p", (cause) => {
        expect(describeSdkFailure("the signer session reported an error", cause)).toBe("the signer session reported an error");
    });
});
