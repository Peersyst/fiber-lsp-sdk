import type { FetchInit, FetchResponseLike, IFetchLike } from "@peersyst/fiber-lsp-sdk";
import { OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD } from "./agent.constants";
import { bareLowerHex } from "./agent.utils";
import { readJsonRpcRequest } from "./json-rpc";

/**
 * Reads the result object of a JSON-RPC answer.
 * @param text The answer's body.
 * @returns The result, or `null` when the answer carries no result object.
 */
function resultObject(text: string): Record<string, unknown> | null {
    let answer: unknown;
    try {
        answer = JSON.parse(text);
    } catch {
        return null;
    }
    if (typeof answer !== "object" || answer === null || !("result" in answer)) return null;
    const { result } = answer;
    return typeof result === "object" && result !== null && !Array.isArray(result) ? (result as Record<string, unknown>) : null;
}

/**
 * Checks that an opening's captured result is there and names the channel the SDK opened.
 * @param raw The result taken from the capture.
 * @param channelId The channel id the SDK returned.
 * @returns The raw result.
 */
export function checkedOpenResult(raw: Record<string, unknown> | null, channelId: string): Record<string, unknown> {
    const method = OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD;
    if (raw === null) throw new Error(`${method}'s result for ${channelId} was not captured`);
    const rawChannelId = raw.channel_id;
    if (typeof rawChannelId !== "string" || bareLowerHex(rawChannelId) !== bareLowerHex(channelId)) {
        throw new Error(`${method}'s result names channel ${String(rawChannelId)}, the SDK opened ${channelId}`);
    }
    return raw;
}

export class OpenResultCapture {
    private captured: Record<string, unknown> | null = null;

    readonly fetch: IFetchLike = (url, init) => this.send(url, init);

    /**
     * Wraps the fetch every request goes through.
     * @param inner The fetch, called without a receiver.
     */
    constructor(private readonly inner: IFetchLike) {}

    /**
     * Hands over the last result kept, and forgets it.
     * @returns The raw result, or `null` when none was kept since the last take.
     */
    take(): Record<string, unknown> | null {
        const captured = this.captured;
        this.captured = null;
        return captured;
    }

    /**
     * Sends a request, keeping the result of an opening.
     * @param url Where to send it.
     * @param init Method, headers and body.
     * @returns The response, its body readable as before.
     */
    private async send(url: string, init: FetchInit): Promise<FetchResponseLike> {
        const send = this.inner;
        const response = await send(url, init);
        if (readJsonRpcRequest(init.body).method !== OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD) return response;
        let text: string;
        try {
            text = await response.text();
        } catch (error) {
            return { status: response.status, text: () => Promise.reject(error) };
        }
        const result = resultObject(text);
        if (result !== null) this.captured = result;
        return { status: response.status, text: () => Promise.resolve(text) };
    }
}
