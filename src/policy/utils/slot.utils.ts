import { assertUnsignedInteger } from "../../common";
import type { NonceContext } from "../../derivation";
import { MAX_COMMITMENT_NUMBER } from "../../derivation";
import { ANNOUNCEMENT_SLOT_NUMBER } from "../policy.constants";
import type { SignOperation, SignOperationKind, SignSlot, SignSlotRef } from "../policy.types";

/**
 * A close shares the commitment slot: fiber derives no closing nonce (`get_funding_sign_context`).
 */
const CONTEXT_BY_OPERATION: Record<SignOperationKind, NonceContext> = {
    commitment_tx: "COMMITMENT",
    shutdown_tx: "COMMITMENT",
    revocation: "REVOKE",
    channel_announcement: "ANNOUNCEMENT",
};

/**
 * Resolves the slot an operation claims, which is the slot its nonce comes from.
 * @param operation Operation the request asks for.
 * @param nonceCommitmentNumber Commitment number the nonce is derived at; ignored for the fixed announcement slot.
 * @returns The claimed slot.
 */
export function resolveSignSlot(operation: SignOperation, nonceCommitmentNumber: number): SignSlotRef {
    const context = CONTEXT_BY_OPERATION[operation.kind] as NonceContext | undefined;
    if (context === undefined) {
        throw new TypeError(`operation.kind must be one of ${Object.keys(CONTEXT_BY_OPERATION).join(", ")}`);
    }
    if (context === "ANNOUNCEMENT") {
        return { context, commitmentNumber: ANNOUNCEMENT_SLOT_NUMBER };
    }
    assertUnsignedInteger("nonceCommitmentNumber", nonceCommitmentNumber, MAX_COMMITMENT_NUMBER);
    return { context, commitmentNumber: nonceCommitmentNumber };
}

/**
 * Builds the registry key of a slot.
 * @param slot Slot to key.
 * @returns The `<context>:<number>` key.
 */
export function signSlotKey(slot: SignSlotRef): SignSlot {
    return `${slot.context}:${slot.commitmentNumber}`;
}
