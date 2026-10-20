import { assertUnsignedInteger, isPlainObject } from "../../common";
import type { NonceContext } from "../../derivation";
import { MAX_COMMITMENT_NUMBER } from "../../derivation";
import { ANNOUNCEMENT_SLOT_NUMBER } from "../policy.constants";
import type {
    NonceCounter,
    PolicySignRequest,
    SignOperation,
    SignOperationKind,
    SignSlot,
    SignSlotClaim,
    SignSlotRef,
    SigningLane,
} from "../policy.types";

// A close shares the commitment slot: fiber derives no closing nonce (`get_funding_sign_context`).
const CONTEXT_BY_OPERATION: Record<SignOperationKind, NonceContext> = {
    commitment_tx: "COMMITMENT",
    closing_tx: "COMMITMENT",
    revocation: "REVOKE",
    channel_announcement: "ANNOUNCEMENT",
};

/**
 * Resolves the slot an operation claims, the one its nonce comes from, and its lane.
 * @param operation Operation the request asks for.
 * @param slot The slot's number and the counter the node read it from.
 * @returns The claimed slot and its lane.
 */
export function resolveSignSlot(operation: SignOperation, slot: PolicySignRequest["slot"]): SignSlotClaim {
    const context = CONTEXT_BY_OPERATION[operation.kind] as NonceContext | undefined;
    if (context === undefined) {
        throw new TypeError(`operation.kind must be one of ${Object.keys(CONTEXT_BY_OPERATION).join(", ")}`);
    }
    if (!isPlainObject(slot)) throw new TypeError("slot must be an object");
    const { commitmentNumber, counter } = slot;
    assertUnsignedInteger("slot.commitmentNumber", commitmentNumber, MAX_COMMITMENT_NUMBER);
    const { counter: expected, lane } = laneOf(operation);
    if (counter !== expected) {
        throw new TypeError(`slot.counter must be ${expected ?? "null"} for a ${operation.kind}, the counter fiber reads its slot from`);
    }
    if (context === "ANNOUNCEMENT" && commitmentNumber !== ANNOUNCEMENT_SLOT_NUMBER) {
        throw new TypeError(`slot.commitmentNumber must be ${ANNOUNCEMENT_SLOT_NUMBER} for a channel_announcement`);
    }
    return { context, commitmentNumber, lane };
}

/**
 * Builds the registry key of a slot.
 * @param slot Slot to key.
 * @returns The `<context>:<number>` key.
 */
export function signSlotKey(slot: SignSlotRef): SignSlot {
    return `${slot.context}:${slot.commitmentNumber}`;
}

/**
 * Names the counter fiber reads an operation's slot from, and the lane that counter orders.
 * @param operation The operation.
 * @returns The counter, `null` for the announcement, and its lane.
 */
function laneOf(operation: SignOperation): { counter: NonceCounter | null; lane: SigningLane } {
    switch (operation.kind) {
        case "commitment_tx":
        case "closing_tx":
            return { counter: "local", lane: "COMMITMENT:local" };
        // Sending revokes the device's own commitment, versioned by the remote number; receiving, the peer's, by the local one.
        case "revocation":
            return operation.input.forRemote ? { counter: "local", lane: "REVOKE:local" } : { counter: "remote", lane: "REVOKE:remote" };
        case "channel_announcement":
            return { counter: null, lane: "ANNOUNCEMENT" };
    }
}
