export type SessionErrorKind =
    | "authentication_failed"
    | "handshake_refused"
    | "version_mismatch"
    | "protocol_violation"
    | "not_connected"
    | "connection_lost"
    | "disconnected";

export class SessionError extends Error {
    readonly kind: SessionErrorKind;

    /**
     * Creates a failure of the session's own.
     * @param kind What failed.
     * @param message Detail, safe to log.
     * @param options The cause, if any.
     */
    constructor(kind: SessionErrorKind, message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "SessionError";
        this.kind = kind;
    }
}

export class BridgeError extends Error {
    readonly code: string;

    /**
     * Creates the failure a bridge `error` frame reported.
     * @param code The bridge's code.
     * @param message The bridge's message.
     */
    constructor(code: string, message: string) {
        super(message);
        this.name = "BridgeError";
        this.code = code;
    }
}
