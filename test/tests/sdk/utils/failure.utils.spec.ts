import { RpcError } from "../../../../src/rpc";
import type { SdkEvent } from "../../../../src/sdk";
import { SdkError, describeSdkFailure, emitPollFailure, emitSdkEvent } from "../../../../src/sdk";

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

describe("emitSdkEvent", () => {
    it("hands the event to the emitter as it is", () => {
        const events: SdkEvent[] = [];
        const event: SdkEvent = { type: "CHANNEL_READY", channelId: `0x${"11".repeat(32)}` };
        emitSdkEvent((emitted) => events.push(emitted), event);
        expect(events).toHaveLength(1);
        expect(events[0]).toBe(event);
    });

    it("swallows what the emitter throws", () => {
        const emit = jest.fn(() => {
            throw new Error("the host's listener failed");
        });
        expect(() => emitSdkEvent(emit, { type: "PAYMENT_PENDING", paymentHashHex: `0x${"22".repeat(32)}` })).not.toThrow();
        expect(emit).toHaveBeenCalledTimes(1);
    });
});

describe("emitPollFailure", () => {
    it("emits one poll_failed error that says what failed and why, the cause attached", () => {
        const events: SdkEvent[] = [];
        const cause = new RpcError("list_channels", -32000, "node is syncing");
        emitPollFailure((event) => events.push(event), "a poll of the node failed", cause);
        expect(events).toHaveLength(1);
        const [event] = events;
        if (event?.type !== "ERROR") throw new Error(`expected an ERROR, got ${event?.type}`);
        expect(event.error).toBeInstanceOf(SdkError);
        expect(event.error.code).toBe("poll_failed");
        expect(event.error.message).toBe("a poll of the node failed: node is syncing");
        expect(event.error.cause).toBe(cause);
    });

    it("keeps a cause that is not an error, saying only what failed", () => {
        const events: SdkEvent[] = [];
        emitPollFailure((event) => events.push(event), "the signing poll failed", "boom");
        expect(events).toMatchObject([
            { type: "ERROR", error: { code: "poll_failed", message: "the signing poll failed", cause: "boom" } },
        ]);
    });

    it("swallows what the emitter throws", () => {
        const emit = jest.fn(() => {
            throw new Error("the host's listener failed");
        });
        expect(() => emitPollFailure(emit, "a poll of the node failed", new Error("socket error"))).not.toThrow();
        expect(emit).toHaveBeenCalledTimes(1);
    });
});
