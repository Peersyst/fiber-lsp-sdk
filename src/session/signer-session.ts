import { SCHNORR_SIGNATURE_LENGTH, X_ONLY_PUBLIC_KEY_LENGTH, assertBytes, isUnsignedInteger } from "../common";
import type { InboundFrame, OutboundFrame, SignError, SignRequest } from "../protocol";
import { PROTOCOL_VERSION, ProtocolError, decodeInboundFrame, encodeOutboundFrame } from "../protocol";
import type { DispatchOutcome, PendingChannelRegistration } from "../signer";
import { asWireError } from "../wire";
import type { ISessionAuthenticator, ISessionHandler, IWebSocketLike, WebSocketCloseEvent, WebSocketFactory } from "./interfaces";
import {
    CLOSE_REASONS,
    DEFAULT_CONNECT_TIMEOUT_MS,
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    DEFAULT_HEARTBEAT_TIMEOUT_MS,
    DEFAULT_RECONNECT_POLICY,
    MAX_DELAY_MS,
    NORMAL_CLOSE_CODE,
} from "./session.constants";
import { BridgeError, SessionError } from "./session.error";
import type { ReconnectPolicy, SessionEvent, SessionListener, SessionOptions, SessionState } from "./session.types";
import { TimerSlot, backoffDelayMs } from "./utils";

type ConnectWaiter = { resolve: () => void; reject: (error: SessionError) => void };

type PendingRegistration = {
    pending: PendingChannelRegistration;
    resolve: (channelId: string) => void;
    reject: (cause: unknown) => void;
};

// Acknowledgements outlive the socket, since nothing re-delivers them.
type Work =
    | { kind: "sign_request"; socket: IWebSocketLike; request: SignRequest }
    | { kind: "sign_refusal"; socket: IWebSocketLike; requestId: string; error: SignError }
    | { kind: "channel_registered"; registration: PendingRegistration; channelId: string }
    | { kind: "error"; registration: PendingRegistration; cause: BridgeError };

export class SignerSession {
    private readonly url: string;

    private readonly createWebSocket: WebSocketFactory;

    private readonly authenticator: ISessionAuthenticator;

    private readonly handler: ISessionHandler;

    private readonly connectTimeoutMs: number;

    private readonly heartbeatIntervalMs: number;

    private readonly heartbeatTimeoutMs: number;

    private readonly reconnect: ReconnectPolicy;

    private readonly random: () => number;

    private currentState: SessionState = "idle";

    private socket: IWebSocketLike | undefined;

    private readonly listeners = new Set<SessionListener>();

    private readonly connectWaiters: ConnectWaiter[] = [];

    private readonly registrations = new Map<string, PendingRegistration>();

    private readonly queue: Work[] = [];

    private pumping = false;

    private attempts = 0;

    private nextRequestId = 0;

    private readonly connectTimeout: TimerSlot;

    private readonly heartbeat: TimerSlot;

    private readonly backoff: TimerSlot;

    /**
     * Creates a session; nothing connects until `connect()`.
     * @param options Session options.
     */
    constructor(options: SessionOptions) {
        this.url = options.url;
        this.createWebSocket = options.createWebSocket;
        this.connectTimeout = new TimerSlot(options.timer);
        this.heartbeat = new TimerSlot(options.timer);
        this.backoff = new TimerSlot(options.timer);
        this.authenticator = options.authenticator;
        this.handler = options.handler;
        this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
        this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
        this.heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;
        this.reconnect = { ...DEFAULT_RECONNECT_POLICY, ...options.reconnect };
        this.random = options.random ?? Math.random;
        assertDelayMs("connectTimeoutMs", this.connectTimeoutMs, 1);
        assertDelayMs("heartbeatIntervalMs", this.heartbeatIntervalMs, 0);
        assertDelayMs("heartbeatTimeoutMs", this.heartbeatTimeoutMs, 1);
        assertDelayMs("reconnect.initialDelayMs", this.reconnect.initialDelayMs, 1);
        assertDelayMs("reconnect.maxDelayMs", this.reconnect.maxDelayMs, this.reconnect.initialDelayMs);
        if (!(typeof this.reconnect.factor === "number" && Number.isFinite(this.reconnect.factor) && this.reconnect.factor >= 1)) {
            throw new RangeError(`reconnect.factor must be a finite number of at least 1, got ${this.reconnect.factor}`);
        }
    }

    get state(): SessionState {
        return this.currentState;
    }

    /**
     * Subscribes to state changes and errors.
     * @param listener The listener; whatever it throws is swallowed.
     * @returns A function that unsubscribes it.
     */
    onEvent(listener: SessionListener): () => void {
        this.listeners.add(listener);
        return () => {
            this.listeners.delete(listener);
        };
    }

    /**
     * Asks to be connected: starts a session, joins one being established, or cuts a backoff short.
     * @returns Resolves once the session is established; rejects when it cannot be, or on `disconnect()`.
     */
    connect(): Promise<void> {
        if (this.currentState === "established" && this.socket) return Promise.resolve();
        const promise = new Promise<void>((resolve, reject) => this.connectWaiters.push({ resolve, reject }));
        if (this.currentState === "idle" || this.currentState === "closed") {
            this.attempts = 0;
            this.open();
        } else if (this.currentState === "reconnecting") {
            this.backoff.clear();
            this.open();
        }
        return promise;
    }

    /**
     * Closes the session and stops reconnecting; the bridge re-delivers whatever was in flight.
     */
    disconnect(): void {
        if (this.currentState === "idle" || this.currentState === "closed") return;
        this.teardown(CLOSE_REASONS.disconnect);
        const reject = this.takeWaiting();
        this.setState("closed");
        reject(new SessionError("disconnected", "disconnect() was called"));
    }

    /**
     * Registers a channel with the node and waits for the name it gives it.
     * @param pending The registration as the dispatch prepared it.
     * @returns The channel id the node assigned, once the handler has filed the channel under it.
     */
    async registerChannel(pending: PendingChannelRegistration): Promise<string> {
        if (this.currentState !== "established" || !this.socket) {
            throw new SessionError("not_connected", `registerChannel needs an established session, the session is ${this.currentState}`);
        }
        const requestId = String(++this.nextRequestId);
        const promise = new Promise<string>((resolve, reject) => this.registrations.set(requestId, { pending, resolve, reject }));
        if (!this.send(this.socket, { type: "register_channel", requestId, registration: pending.registration })) {
            this.registrations.delete(requestId);
            throw new SessionError("connection_lost", "the socket refused the register_channel frame");
        }
        return promise;
    }

    /**
     * Opens a socket and waits for the bridge's challenge.
     */
    private open(): void {
        this.setState("connecting");
        // A listener may have disconnected meanwhile, or already reconnected.
        if (this.currentState !== "connecting" || this.socket) return;
        let socket: IWebSocketLike;
        try {
            socket = this.createWebSocket(this.url);
        } catch (cause) {
            this.scheduleReconnect();
            this.emit({ type: "error", cause });
            return;
        }
        this.socket = socket;
        socket.onmessage = (event) => this.onMessage(socket, event.data);
        socket.onclose = (event) => this.onClose(socket, event);
        socket.onerror = (cause) => this.onError(socket, cause);
        this.connectTimeout.arm(() => this.giveUp(CLOSE_REASONS.connectTimeout), this.connectTimeoutMs);
    }

    /**
     * Decodes a socket message and routes its frame.
     * @param socket The socket that delivered it.
     * @param data What it delivered.
     */
    private onMessage(socket: IWebSocketLike, data: unknown): void {
        if (socket !== this.socket) return;
        this.armHeartbeat(socket);
        let frame: InboundFrame;
        try {
            frame = decodeInboundFrame(data);
        } catch (thrown) {
            const error = asWireError(thrown);
            if (this.currentState === "established" && error instanceof ProtocolError) {
                this.enqueue({
                    socket,
                    kind: "sign_refusal",
                    requestId: error.requestId,
                    error: { code: error.code, message: error.message },
                });
            } else {
                this.violation(error.message);
            }
            return;
        }
        if (this.currentState === "established") this.onEstablishedFrame(socket, frame);
        else this.onHandshakeFrame(socket, frame);
    }

    /**
     * Answers the challenge, then checks `session_established`.
     * @param socket The socket the frame arrived on.
     * @param frame The frame.
     */
    private onHandshakeFrame(socket: IWebSocketLike, frame: InboundFrame): void {
        if (this.currentState === "connecting" && frame.type === "challenge") {
            let signature: Uint8Array;
            try {
                signature = this.authenticator.signChallenge(frame.challenge);
                // Not left to the encoder, whose throw would read as a lost socket and reconnect forever.
                assertBytes("signature", signature, SCHNORR_SIGNATURE_LENGTH);
                assertBytes("publicKey", this.authenticator.publicKey, X_ONLY_PUBLIC_KEY_LENGTH);
            } catch (cause) {
                const error = new SessionError("authentication_failed", "the authenticator could not answer the challenge", { cause });
                this.fail(error, CLOSE_REASONS.authenticationFailed);
                return;
            }
            if (!this.send(socket, { type: "signed_challenge", publicKey: this.authenticator.publicKey, signature })) {
                this.giveUp(CLOSE_REASONS.sendFailed, "the socket refused the signed_challenge frame");
                return;
            }
            this.setState("authenticating");
        } else if (this.currentState === "authenticating" && frame.type === "session_established") {
            if (frame.protocolVersion !== PROTOCOL_VERSION) {
                const message = `the bridge speaks protocol version ${frame.protocolVersion}, this device speaks ${PROTOCOL_VERSION}`;
                this.fail(new SessionError("version_mismatch", message), CLOSE_REASONS.versionMismatch);
                return;
            }
            this.establish(socket);
        } else {
            this.violation(`unexpected ${frame.type} frame while ${this.currentState}`);
        }
    }

    /**
     * Routes a frame of an established session.
     * @param socket The socket the frame arrived on.
     * @param frame The frame.
     */
    private onEstablishedFrame(socket: IWebSocketLike, frame: InboundFrame): void {
        switch (frame.type) {
            case "ping":
                this.send(socket, { type: "pong" });
                return;
            case "pong":
                return;
            case "sign_request":
                this.enqueue({ socket, kind: "sign_request", request: frame.request });
                return;
            case "channel_registered": {
                const registration = this.takeRegistration(frame.requestId, frame.type);
                if (registration) this.enqueue({ kind: "channel_registered", registration, channelId: frame.channelId });
                return;
            }
            case "error": {
                const registration = this.takeRegistration(frame.requestId, frame.type);
                if (registration) this.enqueue({ kind: "error", registration, cause: new BridgeError(frame.code, frame.message) });
                return;
            }
            case "challenge":
            case "session_established":
                this.violation(`unexpected ${frame.type} frame while ${this.currentState}`);
        }
    }

    /**
     * Reports an unreadable or unexpected frame.
     * @param detail What was wrong.
     */
    private violation(detail: string): void {
        const error = new SessionError("protocol_violation", detail);
        if (this.currentState === "established") this.emit({ type: "error", cause: error });
        else this.fail(error, CLOSE_REASONS.protocolViolation);
    }

    /**
     * Marks the session established and resolves `connect()`.
     * @param socket The established socket.
     */
    private establish(socket: IWebSocketLike): void {
        this.connectTimeout.clear();
        this.attempts = 0;
        this.setState("established");
        // A listener may have ended it; the waiters then wait on the next session.
        if (this.currentState !== "established") return;
        this.armHeartbeat(socket);
        for (const waiter of this.connectWaiters.splice(0)) waiter.resolve();
    }

    /**
     * Ends the session for good, rejecting whoever waits on it.
     * @param error Why.
     * @param reason Close reason to send; `undefined` when the bridge closed the socket.
     */
    private fail(error: SessionError, reason: string | undefined): void {
        this.teardown(reason);
        const reject = this.takeWaiting();
        this.setState("closed");
        this.emit({ type: "error", cause: error });
        reject(error);
    }

    /**
     * Closes the socket and schedules the reconnect.
     * @param reason Close reason to send.
     * @param detail Error message, when the reason alone does not say it.
     */
    private giveUp(reason: string, detail: string = reason): void {
        this.teardown(reason);
        this.lost(new SessionError("connection_lost", detail));
    }

    /**
     * Handles the socket closing under the session: refused while authenticating, lost otherwise.
     * @param socket The socket that closed.
     * @param event The close event.
     */
    private onClose(socket: IWebSocketLike, event: WebSocketCloseEvent): void {
        if (socket !== this.socket) return;
        const detail = `socket closed (code ${event.code ?? "none"}, reason "${event.reason ?? ""}")`;
        if (this.currentState === "authenticating") {
            this.fail(new SessionError("handshake_refused", `the bridge closed the socket during authentication: ${detail}`), undefined);
            return;
        }
        this.teardown(undefined);
        this.lost(new SessionError("connection_lost", detail));
    }

    /**
     * Reports a lost socket, rejects its registrations and schedules the reconnect.
     * @param error What happened.
     */
    private lost(error: SessionError): void {
        const registrations = this.takeRegistrations();
        this.scheduleReconnect();
        this.emit({ type: "error", cause: error });
        for (const registration of registrations) registration.reject(error);
    }

    /**
     * Reports a socket error; the close that follows it is what moves the session.
     * @param socket The socket that errored.
     * @param cause The error event.
     */
    private onError(socket: IWebSocketLike, cause: unknown): void {
        if (socket !== this.socket) return;
        this.emit({ type: "error", cause });
    }

    /**
     * Waits out the backoff, then opens again.
     */
    private scheduleReconnect(): void {
        if (this.currentState === "closed") return;
        const delay = backoffDelayMs(this.reconnect, this.attempts, this.random);
        this.attempts += 1;
        // Armed before setState, so a listener's disconnect() can clear it.
        this.backoff.arm(() => this.open(), delay);
        this.setState("reconnecting");
    }

    /**
     * Restarts the heartbeat: a ping after the interval of silence, a lost socket after the timeout.
     * @param socket The established socket.
     */
    private armHeartbeat(socket: IWebSocketLike): void {
        if (this.currentState !== "established" || this.heartbeatIntervalMs === 0) return;
        this.heartbeat.arm(() => {
            if (!this.send(socket, { type: "ping" })) {
                this.giveUp(CLOSE_REASONS.sendFailed, "the socket refused the ping frame");
                return;
            }
            this.heartbeat.arm(() => this.giveUp(CLOSE_REASONS.heartbeatTimeout), this.heartbeatTimeoutMs);
        }, this.heartbeatIntervalMs);
    }

    /**
     * Queues work behind whatever is being processed.
     * @param work The work.
     */
    private enqueue(work: Work): void {
        this.queue.push(work);
        void this.pump();
    }

    /**
     * Processes the queue one item at a time, in arrival order.
     */
    private async pump(): Promise<void> {
        if (this.pumping) return;
        this.pumping = true;
        try {
            for (let work = this.queue.shift(); work !== undefined; work = this.queue.shift()) await this.process(work);
        } finally {
            this.pumping = false;
        }
    }

    /**
     * Processes one queued item.
     * @param work The item.
     */
    private async process(work: Work): Promise<void> {
        switch (work.kind) {
            case "sign_request": {
                const outcome = await this.handle(work.request);
                if (outcome.kind === "fault") {
                    this.emit({ type: "error", cause: outcome.cause });
                    return;
                }
                const requestId = work.request.requestId;
                const response: OutboundFrame =
                    outcome.kind === "result"
                        ? { type: "sign_response", requestId, result: outcome.result }
                        : { type: "sign_response", requestId, error: outcome.error };
                this.answer(work.socket, response);
                return;
            }
            case "sign_refusal":
                this.answer(work.socket, { type: "sign_response", requestId: work.requestId, error: work.error });
                return;
            case "channel_registered":
                try {
                    await this.handler.channelRegistered(work.channelId, work.registration.pending);
                    work.registration.resolve(work.channelId);
                } catch (cause) {
                    work.registration.reject(cause);
                }
                return;
            case "error":
                work.registration.reject(work.cause);
        }
    }

    /**
     * Runs the handler over a request, reading anything it throws as a fault.
     * @param request The request.
     * @returns The outcome.
     */
    private async handle(request: SignRequest): Promise<DispatchOutcome> {
        try {
            return await this.handler.handle(request);
        } catch (cause) {
            return { kind: "fault", cause };
        }
    }

    /**
     * Answers on the socket that delivered the request, or drops the answer if that socket is gone.
     * @param socket The socket the request came on.
     * @param frame The answer.
     */
    private answer(socket: IWebSocketLike, frame: OutboundFrame): void {
        if (socket !== this.socket) return;
        this.send(socket, frame);
    }

    /**
     * Takes a pending registration out of correlation, reporting an id that matches none.
     * @param requestId The id the frame carried.
     * @param frameType The frame's type, for the report.
     * @returns The registration, if any.
     */
    private takeRegistration(requestId: string, frameType: string): PendingRegistration | undefined {
        const registration = this.registrations.get(requestId);
        if (!registration) {
            this.emit({
                type: "error",
                cause: new SessionError("protocol_violation", `${frameType} frame for an unknown request id ${requestId}`),
            });
            return undefined;
        }
        this.registrations.delete(requestId);
        return registration;
    }

    /**
     * Takes every pending registration out of correlation.
     * @returns The registrations.
     */
    private takeRegistrations(): PendingRegistration[] {
        const registrations = [...this.registrations.values()];
        this.registrations.clear();
        return registrations;
    }

    /**
     * Takes out the current waiters, before a state listener can add the next session's.
     * @returns A function that rejects them.
     */
    private takeWaiting(): (error: SessionError) => void {
        const waiters = this.connectWaiters.splice(0);
        const registrations = this.takeRegistrations();
        return (error) => {
            for (const waiter of waiters) waiter.reject(error);
            for (const registration of registrations) registration.reject(error);
        };
    }

    /**
     * Writes a frame to a socket.
     * @param socket The socket.
     * @param frame The frame.
     * @returns Whether the socket took it; a failure is reported as an error event.
     */
    private send(socket: IWebSocketLike, frame: OutboundFrame): boolean {
        try {
            socket.send(encodeOutboundFrame(frame));
            return true;
        } catch (cause) {
            this.emit({ type: "error", cause });
            return false;
        }
    }

    /**
     * Drops the current socket, every timer, and the queued requests it delivered.
     * @param reason Close reason to send; `undefined` when the bridge closed the socket.
     */
    private teardown(reason: string | undefined): void {
        this.connectTimeout.clear();
        this.heartbeat.clear();
        this.backoff.clear();
        const acknowledgements = this.queue.filter((work) => work.kind === "channel_registered" || work.kind === "error");
        this.queue.splice(0, this.queue.length, ...acknowledgements);
        const socket = this.socket;
        if (!socket) return;
        this.socket = undefined;
        socket.onmessage = null;
        socket.onclose = null;
        socket.onerror = null;
        if (reason === undefined) return;
        try {
            socket.close(NORMAL_CLOSE_CODE, reason);
        } catch (cause) {
            this.emit({ type: "error", cause });
        }
    }

    /**
     * Moves to a state and tells the listeners.
     * @param state The new state.
     */
    private setState(state: SessionState): void {
        this.currentState = state;
        this.emit({ type: "state", state });
    }

    /**
     * Delivers an event to every listener; a listener that throws never breaks the session.
     * @param event The event.
     */
    private emit(event: SessionEvent): void {
        for (const listener of [...this.listeners]) {
            try {
                listener(event);
            } catch {
                // A listener's failure is the host's, not the session's.
            }
        }
    }
}

/**
 * Asserts that a timing option is a whole number of milliseconds a timer can take.
 * @param name Name of the option, used in the error message.
 * @param value Value to check.
 * @param min Lowest accepted value, inclusive.
 */
function assertDelayMs(name: string, value: number, min: number): void {
    if (!isUnsignedInteger(value, MAX_DELAY_MS) || value < min) {
        throw new RangeError(`${name} must be an integer between ${min} and ${MAX_DELAY_MS}, got ${value}`);
    }
}
