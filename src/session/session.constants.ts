import type { ReconnectPolicy } from "./session.types";

export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

export const DEFAULT_HEARTBEAT_INTERVAL_MS = 20_000;

export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 10_000;

export const DEFAULT_RECONNECT_POLICY: ReconnectPolicy = { initialDelayMs: 1_000, factor: 2, maxDelayMs: 30_000 };

/**
 * Past a signed 32-bit delay, `setTimeout` fires immediately.
 */
export const MAX_DELAY_MS = 2 ** 31 - 1;

/**
 * The only code below 3000 that a browser lets a client close with.
 */
export const NORMAL_CLOSE_CODE = 1000;

export const CLOSE_REASONS = {
    disconnect: "disconnect",
    authenticationFailed: "authentication failed",
    connectTimeout: "connect timeout",
    heartbeatTimeout: "heartbeat timeout",
    protocolViolation: "protocol violation",
    sendFailed: "send failed",
    versionMismatch: "protocol version mismatch",
} as const;
