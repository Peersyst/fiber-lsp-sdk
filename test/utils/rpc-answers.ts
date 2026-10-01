import type { WireField } from "../../src/wire";
import { FetchMock } from "../mocks/rpc";

export const RPC_RESULT_PATH = "response.result";

export function resultField(value: unknown): WireField {
    return { value, path: RPC_RESULT_PATH };
}

// Answers only a client's first call, id 1.
export function answering(result: unknown): FetchMock {
    return new FetchMock().answer({ status: 200, body: JSON.stringify({ jsonrpc: "2.0", id: 1, result }) });
}

export function refusing(code: number, message: string): FetchMock {
    return new FetchMock().answer({ status: 200, body: JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code, message } }) });
}

export function sent(mock: FetchMock): unknown {
    return JSON.parse(mock.last.init.body);
}
