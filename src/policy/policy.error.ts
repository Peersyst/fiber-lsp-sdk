import type { SignerErrorCode } from "../common";
import type { ChannelPinConflict, DebitIntentErrorCode, HoldInvoiceErrorCode } from "./policy.types";

export class PolicyRefusalError extends Error {
    readonly code: SignerErrorCode;

    /**
     * Creates a refusal.
     * @param code Wire error code the node is answered with.
     * @param message Reason, safe to log: refusal messages never carry key material.
     */
    constructor(code: SignerErrorCode, message: string) {
        super(message);
        this.name = "PolicyRefusalError";
        this.code = code;
    }
}

/**
 * Refuses a request, ending the pipeline wherever it is.
 * @param code Wire error code the node is answered with.
 * @param message Reason, safe to log.
 */
export function refusePolicyRequest(code: SignerErrorCode, message: string): never {
    throw new PolicyRefusalError(code, message);
}

/**
 * A debit intent the recorded state refuses: the user's doing, not a bug.
 */
export class DebitIntentError extends Error {
    readonly code: DebitIntentErrorCode;

    /**
     * Creates the error.
     * @param code What in the recorded state refused the intent.
     * @param message Reason, safe to log.
     */
    constructor(code: DebitIntentErrorCode, message: string) {
        super(message);
        this.name = "DebitIntentError";
        this.code = code;
    }
}

/**
 * A hold invoice step the recorded state does not allow yet: the host retries later.
 */
export class HoldInvoiceError extends Error {
    readonly code: HoldInvoiceErrorCode;

    /**
     * Creates the error.
     * @param code What in the recorded state holds the step back.
     * @param message Reason, safe to log.
     */
    constructor(code: HoldInvoiceErrorCode, message: string) {
        super(message);
        this.name = "HoldInvoiceError";
        this.code = code;
    }
}

export class FundingCellError extends Error {
    readonly conflict: ChannelPinConflict;

    /**
     * Creates the error.
     * @param channelId The channel, as the host named it.
     * @param conflict The pinned value and the one the host stated.
     */
    constructor(channelId: string, conflict: ChannelPinConflict) {
        super(`channel ${channelId} already pins ${conflict.field} to ${conflict.pinned}, not ${conflict.stated}`);
        this.name = "FundingCellError";
        this.conflict = conflict;
    }
}
