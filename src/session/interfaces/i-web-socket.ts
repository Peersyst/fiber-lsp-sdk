export type WebSocketMessageEvent = { data: unknown };

export type WebSocketCloseEvent = { code?: number; reason?: string };

/**
 * Method syntax makes it bivariant, so the runtimes' own event types assign to it.
 */
type WebSocketHandler<Event> = { handle(event: Event): void }["handle"];

export interface IWebSocketLike {
    /**
     * Sends a text frame.
     * @param data The frame text.
     */
    send(data: string): void;
    /**
     * Closes the socket.
     * @param code Close code.
     * @param reason Close reason.
     */
    close(code?: number, reason?: string): void;
    onmessage: WebSocketHandler<WebSocketMessageEvent> | null;
    onclose: WebSocketHandler<WebSocketCloseEvent> | null;
    onerror: WebSocketHandler<unknown> | null;
}

export type WebSocketFactory = (url: string) => IWebSocketLike;
