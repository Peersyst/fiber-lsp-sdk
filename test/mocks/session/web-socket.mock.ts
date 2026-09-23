import type { IWebSocketLike, WebSocketCloseEvent } from "../../../src/session";

export class WebSocketMock implements IWebSocketLike {
    readonly url: string;

    onmessage: IWebSocketLike["onmessage"] = null;

    onclose: IWebSocketLike["onclose"] = null;

    onerror: IWebSocketLike["onerror"] = null;

    readonly sent: unknown[] = [];

    // Hooks for the server end.
    onSent: ((frame: unknown) => void) | null = null;

    onClosed: ((event: WebSocketCloseEvent) => void) | null = null;

    closedWith: WebSocketCloseEvent | undefined;

    sendError: Error | undefined;

    closeError: Error | undefined;

    constructor(url: string) {
        this.url = url;
    }

    send(data: string): void {
        if (this.sendError) throw this.sendError;
        if (this.closedWith) throw new Error("send on a closed socket");
        const frame: unknown = JSON.parse(data);
        this.sent.push(frame);
        this.onSent?.(frame);
    }

    close(code?: number, reason?: string): void {
        if (this.closeError) throw this.closeError;
        if (this.closedWith) return;
        this.closedWith = { code, reason };
        this.onClosed?.({ code, reason });
        // Runtimes fire the close event asynchronously.
        queueMicrotask(() => this.onclose?.({ code, reason }));
    }

    receive(frame: unknown): Promise<void> {
        const data = isPlainObject(frame) ? JSON.stringify(frame) : frame;
        return deliver(() => this.onmessage?.({ data }));
    }

    closeFromServer(code?: number, reason?: string): Promise<void> {
        return deliver(() => this.onclose?.({ code, reason }));
    }

    error(cause: unknown = new Error("socket error")): Promise<void> {
        return deliver(() => this.onerror?.(cause));
    }
}

export class WebSocketFactoryMock {
    readonly sockets: WebSocketMock[] = [];

    failure: Error | undefined;

    readonly create = (url: string): WebSocketMock => {
        if (this.failure) throw this.failure;
        const socket = new WebSocketMock(url);
        this.sockets.push(socket);
        return socket;
    };

    get last(): WebSocketMock {
        const socket = this.sockets.at(-1);
        if (!socket) throw new Error("no socket has been created");
        return socket;
    }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype;
}

function deliver(action: () => void): Promise<void> {
    return new Promise((resolve) => {
        queueMicrotask(() => {
            action();
            resolve();
        });
    });
}
