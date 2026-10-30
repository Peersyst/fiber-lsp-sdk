import type { FetchInit, FetchResponseLike, IFetchLike } from "@peersyst/fiber-lsp-sdk";

export class FacadeGate {
    private closed = false;

    private inFlight = 0;

    private idle: (() => void)[] = [];

    readonly fetch: IFetchLike = (url, init) => this.send(url, init);

    /**
     * Wraps the fetch the facade's requests go through.
     * @param inner The fetch, called without a receiver.
     */
    constructor(private readonly inner: IFetchLike) {}

    /**
     * Refuses every request the facade sends from now on.
     */
    close(): void {
        this.closed = true;
    }

    /**
     * Waits until no request is in flight, then one macrotask: the store is synchronous, so what follows an answer has run by then.
     * @returns Settles once the facade can no longer write.
     */
    async drained(): Promise<void> {
        if (this.inFlight > 0) await new Promise<void>((resolve) => this.idle.push(resolve));
        await new Promise((resolve) => setImmediate(resolve));
    }

    /**
     * Sends a request while the gate is open, its body read before it counts as answered.
     * @param url Where to send it.
     * @param init Method, headers and body.
     * @returns The response, its body already read.
     */
    private async send(url: string, init: FetchInit): Promise<FetchResponseLike> {
        if (this.closed) throw new Error("the facade was replaced: its requests no longer reach the node");
        this.inFlight++;
        try {
            const send = this.inner;
            const response = await send(url, init);
            let text: string;
            try {
                text = await response.text();
            } catch (error) {
                return { status: response.status, text: () => Promise.reject(error) };
            }
            return { status: response.status, text: () => Promise.resolve(text) };
        } finally {
            this.inFlight--;
            if (this.inFlight === 0) for (const resolve of this.idle.splice(0)) resolve();
        }
    }
}
