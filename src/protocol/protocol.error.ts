import type { SignerErrorCode } from "../common";
import { WireError } from "../wire";

export class ProtocolError extends WireError {
    readonly code: SignerErrorCode = "malformed";

    /**
     * Refuses a signing status not as fiber writes it.
     * @param path Wire path of the field that failed.
     * @param reason What the field had to be, never what it was.
     */
    constructor(path: string, reason: string) {
        super(path, reason);
        this.name = "ProtocolError";
    }
}
