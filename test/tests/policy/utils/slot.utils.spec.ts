import { MAX_COMMITMENT_NUMBER } from "../../../../src/derivation";
import type { SignOperation, SignOperationKind } from "../../../../src/policy";
import { resolveSignSlot, signSlotKey } from "../../../../src/policy/utils";

// Only the kind decides a slot, so these carry no inputs.
function operation(kind: string): SignOperation {
    return { kind, input: {} } as unknown as SignOperation;
}

describe("resolveSignSlot", () => {
    it.each([
        ["commitment_tx", "COMMITMENT"],
        // Fiber derives no closing nonce, so a shutdown signs with the commitment slot.
        ["shutdown_tx", "COMMITMENT"],
        ["revocation", "REVOKE"],
    ] as [SignOperationKind, string][])("claims the %s slot at the nonce number", (kind, context) => {
        expect(resolveSignSlot(operation(kind), 9)).toEqual({ context, commitmentNumber: 9 });
    });

    it("claims the fixed announcement slot whatever number the request carries", () => {
        expect(resolveSignSlot(operation("channel_announcement"), 9)).toEqual({ context: "ANNOUNCEMENT", commitmentNumber: 0 });
    });

    it("accepts the highest commitment number of the chain", () => {
        expect(resolveSignSlot(operation("commitment_tx"), MAX_COMMITMENT_NUMBER)).toEqual({
            context: "COMMITMENT",
            commitmentNumber: MAX_COMMITMENT_NUMBER,
        });
    });

    it("rejects an unknown operation kind", () => {
        expect(() => resolveSignSlot(operation("settlement"), 0)).toThrow(TypeError);
    });

    it.each([
        ["above the chain", MAX_COMMITMENT_NUMBER + 1],
        ["negative", -1],
        ["fractional", 1.5],
        ["not a number", "3" as unknown as number],
    ])("rejects a commitment number %s", (_, commitmentNumber) => {
        expect(() => resolveSignSlot(operation("commitment_tx"), commitmentNumber)).toThrow(RangeError);
    });

    it("ignores an out-of-range number on the announcement slot", () => {
        expect(resolveSignSlot(operation("channel_announcement"), -1)).toEqual({ context: "ANNOUNCEMENT", commitmentNumber: 0 });
    });
});

describe("signSlotKey", () => {
    it.each([
        [{ context: "COMMITMENT" as const, commitmentNumber: 0 }, "COMMITMENT:0"],
        [{ context: "REVOKE" as const, commitmentNumber: 12 }, "REVOKE:12"],
        [{ context: "ANNOUNCEMENT" as const, commitmentNumber: 0 }, "ANNOUNCEMENT:0"],
        [{ context: "CLOSE" as const, commitmentNumber: MAX_COMMITMENT_NUMBER }, `CLOSE:${MAX_COMMITMENT_NUMBER}`],
    ])("keys $context:$commitmentNumber", (slot, key) => {
        expect(signSlotKey(slot)).toBe(key);
    });
});
