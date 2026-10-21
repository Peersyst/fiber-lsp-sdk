import type { WireField } from "../../src/wire";
import type { SentCall } from "../mocks/rpc";
import { FetchMock, rpcErrorAnswer, rpcResultAnswer } from "../mocks/rpc";

export const RPC_RESULT_PATH = "response.result";

export function resultField(value: unknown): WireField {
    return { value, path: RPC_RESULT_PATH };
}

export const LIST_CHANNELS_CALL: SentCall = { method: "list_channels", params: {} };

export function signingStatusCall(channelId: string): SentCall {
    return { method: "get_channel_signing_status", params: { channel_id: channelId } };
}

// Answers only a client's first call, id 1.
export function answering(result: unknown): FetchMock {
    return new FetchMock().answer(rpcResultAnswer(1, result));
}

export function refusing(code: number, message: string): FetchMock {
    return new FetchMock().answer(rpcErrorAnswer(1, code, message));
}

export function sent(mock: FetchMock): unknown {
    return JSON.parse(mock.last.init.body);
}
