import { assertNonEmptyString } from "../common";
import { asWireError } from "../wire";
import type { FetchResponseLike, IFetchLike } from "./interfaces";
import { decodeRpcResponse, encodeRpcRequest } from "./json-rpc";
import { BEARER_PREFIX, JSON_CONTENT_TYPE } from "./rpc.constants";
import { RpcError, RpcResponseError, RpcTransportError } from "./rpc.error";
import type { FiberRpcClientOptions, RpcMethod, RpcParamsWire, RpcResultDecoder } from "./rpc.types";

// A header value every runtime accepts, so a bad token fails at construction.
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;

export class FiberRpcClient {
    private readonly url: string;

    private readonly headers: Record<string, string>;

    private readonly fetch: IFetchLike;

    private nextId = 1;

    /**
     * Creates a client of one fiber node.
     * @param options The node's url, its Biscuit token if any, and the host's fetch.
     */
    constructor(options: FiberRpcClientOptions) {
        assertNonEmptyString("url", options.url);
        this.url = options.url;
        this.headers = { "content-type": JSON_CONTENT_TYPE };
        if (options.token !== undefined) {
            if (!TOKEN_PATTERN.test(options.token)) throw new TypeError("token must be printable ASCII without spaces");
            this.headers.authorization = BEARER_PREFIX + options.token;
        }
        this.fetch = options.fetch;
    }

    /**
     * Calls a method and decodes its result.
     * @param method Method to call.
     * @param params The method's params, in wire form.
     * @param decode Reader of the method's result.
     * @returns The decoded result.
     */
    async call<Result>(method: RpcMethod, params: RpcParamsWire, decode: RpcResultDecoder<Result>): Promise<Result> {
        const id = this.nextId++;
        const text = await this.post(method, encodeRpcRequest(id, method, params));
        const response = readAnswer(method, () => decodeRpcResponse(text, id));
        if ("error" in response) throw new RpcError(method, response.error.code, response.error.message);
        return readAnswer(method, () => decode(response.result));
    }

    /**
     * Posts a request and reads the response body of a 2xx status.
     * @param method Method being called, for the errors.
     * @param body The request text.
     * @returns The response text.
     */
    private async post(method: RpcMethod, body: string): Promise<string> {
        const send = this.fetch;
        let response: FetchResponseLike;
        try {
            response = await send(this.url, { method: "POST", headers: { ...this.headers }, body });
        } catch (cause) {
            throw new RpcTransportError(method, "the request failed", undefined, { cause });
        }
        const { status } = response;
        if (!Number.isInteger(status) || status < 200 || status > 299) throw new RpcTransportError(method, `HTTP status ${status}`, status);
        try {
            return await response.text();
        } catch (cause) {
            throw new RpcTransportError(method, "the response body could not be read", status, { cause });
        }
    }
}

/**
 * Runs a read of the node's answer, turning a wire refusal into an `RpcResponseError`.
 * @param method Method being called.
 * @param read The read to run.
 * @returns What the read returned.
 */
function readAnswer<Value>(method: RpcMethod, read: () => Value): Value {
    try {
        return read();
    } catch (error) {
        throw new RpcResponseError(method, asWireError(error));
    }
}
