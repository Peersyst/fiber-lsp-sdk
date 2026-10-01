import type { WireField } from "../wire";
import { decodeString, malformedWireField, readObject } from "../wire";
import { JSON_RPC_VERSION } from "./rpc.constants";
import type { RpcErrorObjectWire, RpcMethod, RpcParamsWire, RpcRequestWire, RpcResponse, RpcResponseWire } from "./rpc.types";

const RESPONSE_PATH = "response";

/**
 * Writes a call as fiber reads it, the params as the only item of a positional array.
 * @param id Id the response must answer.
 * @param method Method to call.
 * @param params The method's params, in wire form.
 * @returns The JSON text.
 */
export function encodeRpcRequest(id: number, method: RpcMethod, params: RpcParamsWire): string {
    const request: RpcRequestWire = { jsonrpc: JSON_RPC_VERSION, id, method, params: [params] };
    return JSON.stringify(request);
}

/**
 * Reads a response body as the answer to one request.
 * @param text The response body.
 * @param id Id the request was sent with.
 * @returns The result field, still to decode, or the error's code and message.
 */
export function decodeRpcResponse(text: string, id: number): RpcResponse {
    const response: WireField = { value: parseRpcResponse(text), path: RESPONSE_PATH };
    const at = readObject<RpcResponseWire>(response);
    const version = at("jsonrpc");
    if (version.value !== JSON_RPC_VERSION) malformedWireField(version, `must be "${JSON_RPC_VERSION}"`);
    // By presence: a null result is still a result.
    const hasResult = at("result").value !== undefined;
    const hasError = at("error").value !== undefined;
    if (hasResult === hasError) malformedWireField(response, "must carry exactly one of result and error");
    const answered = at("id");
    // A null id answers a request the node could not read.
    const unread = !hasResult && answered.value === null;
    if (answered.value !== id && !unread) malformedWireField(answered, `must be ${id}, the id of the request`);
    return hasResult ? { result: at("result") } : { error: decodeRpcErrorObject(at("error")) };
}

/**
 * Parses a response body as JSON.
 * @param text The response body.
 * @returns The parsed value, still unknown.
 */
function parseRpcResponse(text: string): unknown {
    try {
        return JSON.parse(text) as unknown;
    } catch {
        malformedWireField({ value: text, path: RESPONSE_PATH }, "must be valid JSON");
    }
}

/**
 * Reads a JSON-RPC error object, ignoring its `data`.
 * @param field Field to read.
 * @returns The error's code and message.
 */
function decodeRpcErrorObject(field: WireField): RpcErrorObjectWire {
    const at = readObject<RpcErrorObjectWire>(field);
    const code = at("code");
    if (typeof code.value !== "number" || !Number.isSafeInteger(code.value)) malformedWireField(code, "must be an integer");
    return { code: code.value, message: decodeString(at("message")) };
}
