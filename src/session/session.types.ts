import type { ISessionAuthenticator, ISessionHandler, ITimer, WebSocketFactory } from "./interfaces";

export type SessionState = "idle" | "connecting" | "authenticating" | "established" | "reconnecting" | "closed";

export type SessionEvent = { type: "state"; state: SessionState } | { type: "error"; cause: unknown };

export type SessionListener = (event: SessionEvent) => void;

export type ReconnectPolicy = {
    initialDelayMs: number;
    factor: number;
    maxDelayMs: number;
};

export type SessionOptions = {
    url: string;
    createWebSocket: WebSocketFactory;
    timer: ITimer;
    authenticator: ISessionAuthenticator;
    handler: ISessionHandler;
    connectTimeoutMs?: number;
    /**
     * Inbound silence before the device pings; `0` disables the heartbeat.
     */
    heartbeatIntervalMs?: number;
    heartbeatTimeoutMs?: number;
    reconnect?: Partial<ReconnectPolicy>;
    /**
     * Uniform in `[0, 1)`: the backoff jitter.
     */
    random?: () => number;
};
