export type FetchInit = { method: "POST"; headers: Record<string, string>; body: string };

export type FetchResponseLike = {
    status: number;
    /**
     * Reads the whole body as text.
     * @returns The body.
     */
    text(): Promise<string>;
};

export interface IFetchLike {
    /**
     * Sends one request; called without a receiver, as a browser's `fetch` requires.
     * @param url Where to send it.
     * @param init Method, headers and body.
     * @returns The response, rejecting only when no response arrived.
     */
    (url: string, init: FetchInit): Promise<FetchResponseLike>;
}
