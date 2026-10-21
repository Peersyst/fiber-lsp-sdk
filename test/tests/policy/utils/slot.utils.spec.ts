import { MAX_COMMITMENT_NUMBER } from "../../../../src/derivation";
import type { NonceCounter, SignOperation } from "../../../../src/policy";
import { resolveSignSlot, signSlotKey } from "../../../../src/policy/utils";

// Only the kind decides a slot, and a revocation's direction its lane, so these carry no other input.
function operation(kind: string, forRemote = false): SignOperation {
    return { kind, input: { forRemote } } as unknown as SignOperation;
}

describe("resolveSignSlot", () => {
    it.each([
        ["commitment_tx", false, "local", "COMMITMENT", "COMMITMENT:local"],
        // Fiber derives no closing nonce, so a close signs with the commitment slot, on its lane.
        ["closing_tx", false, "local", "COMMITMENT", "COMMITMENT:local"],
        ["revocation", false, "remote", "REVOKE", "REVOKE:remote"],
        ["revocation", true, "local", "REVOKE", "REVOKE:local"],
    ] as [string, boolean, NonceCounter, string, string][])(
        "claims a %s (for remote: %s) at its number, read from the %s counter",
        (kind, forRemote, counter, context, lane) => {
            expect(resolveSignSlot(operation(kind, forRemote), { commitmentNumber: 9, counter })).toEqual({
                context,
                commitmentNumber: 9,
                lane,
            });
        },
    );

    it("claims the fixed announcement slot, read from no counter", () => {
        expect(resolveSignSlot(operation("channel_announcement"), { commitmentNumber: 0, counter: null })).toEqual({
            context: "ANNOUNCEMENT",
            commitmentNumber: 0,
            lane: "ANNOUNCEMENT",
        });
    });

    it("accepts the highest commitment number of the chain", () => {
        expect(resolveSignSlot(operation("commitment_tx"), { commitmentNumber: MAX_COMMITMENT_NUMBER, counter: "local" })).toEqual({
            context: "COMMITMENT",
            commitmentNumber: MAX_COMMITMENT_NUMBER,
            lane: "COMMITMENT:local",
        });
    });

    it("rejects an unknown operation kind", () => {
        expect(() => resolveSignSlot(operation("settlement"), { commitmentNumber: 0, counter: "local" })).toThrow(
            new TypeError("operation.kind must be one of commitment_tx, closing_tx, revocation, channel_announcement"),
        );
    });

    it.each([null, undefined, 9, []])("rejects a slot that is no object, %p", (slot) => {
        expect(() => resolveSignSlot(operation("commitment_tx"), slot as never)).toThrow(new TypeError("slot must be an object"));
    });

    it.each([
        ["above the chain", MAX_COMMITMENT_NUMBER + 1],
        ["negative", -1],
        ["fractional", 1.5],
        ["not a number", "3"],
        ["absent", undefined],
    ])("rejects a commitment number %s", (_, commitmentNumber) => {
        expect(() => resolveSignSlot(operation("commitment_tx"), { commitmentNumber, counter: "local" } as never)).toThrow(
            new RangeError(
                `slot.commitmentNumber must be an integer between 0 and ${MAX_COMMITMENT_NUMBER}, got ${String(commitmentNumber)}`,
            ),
        );
    });

    it.each([
        ["a commitment read from the remote counter", operation("commitment_tx"), "remote", "local"],
        ["a commitment read from no counter", operation("commitment_tx"), null, "local"],
        ["a close read from the remote counter", operation("closing_tx"), "remote", "local"],
        ["a sent revocation read from the local counter", operation("revocation", false), "local", "remote"],
        ["a received revocation read from the remote counter", operation("revocation", true), "remote", "local"],
        ["a revocation read from no counter", operation("revocation", true), null, "local"],
        ["an announcement read from the local counter", operation("channel_announcement"), "local", "null"],
        ["a counter fiber does not name", operation("commitment_tx"), "Local", "local"],
        ["an absent counter", operation("commitment_tx"), undefined, "local"],
    ])("rejects %s", (_, op, counter, expected) => {
        expect(() => resolveSignSlot(op, { commitmentNumber: 3, counter } as never)).toThrow(
            new TypeError(`slot.counter must be ${expected} for a ${op.kind}, the counter fiber reads its slot from`),
        );
    });

    // The announcement nonce never rotates: a slot that followed the request would be a second nonce space.
    it.each([1, 7, MAX_COMMITMENT_NUMBER])("rejects an announcement at number %p", (commitmentNumber) => {
        expect(() => resolveSignSlot(operation("channel_announcement"), { commitmentNumber, counter: null })).toThrow(
            new TypeError("slot.commitmentNumber must be 0 for a channel_announcement"),
        );
    });
});

describe("signSlotKey", () => {
    it.each([
        [{ context: "COMMITMENT" as const, commitmentNumber: 0 }, "COMMITMENT:0"],
        [{ context: "REVOKE" as const, commitmentNumber: 12 }, "REVOKE:12"],
        [{ context: "ANNOUNCEMENT" as const, commitmentNumber: 0 }, "ANNOUNCEMENT:0"],
        [{ context: "COMMITMENT" as const, commitmentNumber: MAX_COMMITMENT_NUMBER }, `COMMITMENT:${MAX_COMMITMENT_NUMBER}`],
    ])("keys $context:$commitmentNumber", (slot, key) => {
        expect(signSlotKey(slot)).toBe(key);
    });
});
