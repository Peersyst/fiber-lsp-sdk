import type { SdkErrorCode } from "./sdk.types";

export class SdkError extends Error {
    readonly code: SdkErrorCode;

    /**
     * Creates a facade error over the module's own as its cause.
     * @param code What failed.
     * @param message Detail, safe to log.
     * @param options The cause, if any.
     */
    constructor(code: SdkErrorCode, message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "SdkError";
        this.code = code;
    }
}
