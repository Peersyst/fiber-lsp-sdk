import type { SignerErrorCode } from "../common";
import { WireError } from "../wire";

export class ProtocolError extends WireError {
    readonly code: SignerErrorCode = "malformed";

    readonly requestId: string;

    /**
     * Creates a refusal that can be answered: the malformed field, and the request that answers it.
     * @param path Wire path of the field that failed, the only thing a refusal names.
     * @param reason What the field had to be, never what it was.
     * @param requestId Id of the sign request the refusal is answered with.
     */
    constructor(path: string, reason: string, requestId: string) {
        super(path, reason);
        this.name = "ProtocolError";
        this.requestId = requestId;
    }
}
