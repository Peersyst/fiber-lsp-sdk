import type { SignerErrorCode } from "../protocol";

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
export function refuse(code: SignerErrorCode, message: string): never {
    throw new PolicyRefusalError(code, message);
}
