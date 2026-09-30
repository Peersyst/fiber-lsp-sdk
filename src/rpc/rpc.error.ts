import type { WireError } from "../wire";
import type { RpcMethod } from "./rpc.types";

export class RpcTransportError extends Error {
    readonly method: RpcMethod;

    readonly status: number | undefined;

    /**
     * Creates a failure after which the call may or may not have run.
     * @param method Method that was called.
     * @param message What failed.
     * @param status The HTTP status, when a response arrived.
     * @param options The cause, if any.
     */
    constructor(method: RpcMethod, message: string, status?: number, options?: ErrorOptions) {
        super(`${method}: ${message}`, options);
        this.name = "RpcTransportError";
        this.method = method;
        this.status = status;
    }
}

export class RpcError extends Error {
    readonly method: RpcMethod;

    readonly code: number;

    /**
     * Creates the refusal the node answered with.
     * @param method Method that was called.
     * @param code The node's JSON-RPC error code.
     * @param message The node's message, verbatim.
     */
    constructor(method: RpcMethod, code: number, message: string) {
        super(message);
        this.name = "RpcError";
        this.method = method;
        this.code = code;
    }
}

export class RpcResponseError extends Error {
    readonly method: RpcMethod;

    readonly path: string;

    readonly reason: string;

    /**
     * Creates a failure to read what the node answered.
     * @param method Method that was called.
     * @param cause The refusal of the field that could not be read.
     */
    constructor(method: RpcMethod, cause: WireError) {
        super(`${method}: ${cause.message}`, { cause });
        this.name = "RpcResponseError";
        this.method = method;
        this.path = cause.path;
        this.reason = cause.reason;
    }
}
