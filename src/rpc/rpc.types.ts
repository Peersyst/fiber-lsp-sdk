import type { Field } from "../wire";
import type { IFetchLike } from "./interfaces";
import type { JSON_RPC_VERSION, RPC_METHODS } from "./rpc.constants";

export type RpcMethod = (typeof RPC_METHODS)[number];

export type RpcParamsWire = Record<string, unknown>;

export type RpcRequestWire = { jsonrpc: typeof JSON_RPC_VERSION; id: number; method: RpcMethod; params: [RpcParamsWire] };

export type RpcErrorObjectWire = { code: number; message: string };

export type RpcResponseWire = { jsonrpc: string; id: number | null; result: unknown; error: RpcErrorObjectWire };

export type RpcResponse = { result: Field } | { error: RpcErrorObjectWire };

export type RpcResultDecoder<Result> = (field: Field) => Result;

export type FiberRpcClientOptions = {
    url: string;
    /**
     * Biscuit token, base64; omitted when the node's RPC has no auth.
     */
    token?: string;
    fetch: IFetchLike;
};
