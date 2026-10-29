import type { FetchInit, FetchResponseLike, IFetchLike } from "@peersyst/fiber-lsp-sdk";

const CAPTURED_METHOD = "open_tenant_channel";

/**
 * Reads the JSON-RPC method a request body calls.
 * @param body The request body.
 * @returns The method, or `null` when the body names none.
 */
function requestMethod(body: string): string | null {
    let request: unknown;
    try {
        request = JSON.parse(body);
    } catch {
        return null;
    }
    if (typeof request !== "object" || request === null || !("method" in request)) return null;
    return typeof request.method === "string" ? request.method : null;
}

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
     * Sends a request, reading the answer of an opening to keep its result and handing the SDK the same text.
     * @param url Where to send it.
     * @param init Method, headers and body.
     * @returns The response, its body readable as before.
     */
    private async send(url: string, init: FetchInit): Promise<FetchResponseLike> {
        const send = this.inner;
        const response = await send(url, init);
        if (requestMethod(init.body) !== CAPTURED_METHOD) return response;
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
