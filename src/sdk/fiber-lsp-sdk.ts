import {
    ListenerSet,
    assertBytes,
    assertCompressedPoint,
    assertFunction,
    isPlainObject,
    assertNonEmptyString,
    assertTimerDelayMs,
} from "../common";
import { MASTER_SEED_LENGTH } from "../derivation";
import { PolicyEngine, SignerStore } from "../policy";
import { FiberRpcClient } from "../rpc";
import type { SessionEvent, SessionState } from "../session";
import { SignerSession } from "../session";
import { SignerDispatch, WalletIdentity } from "../signer";
import { ActivityTracker } from "./activity";
import { IndexAllocator } from "./allocator";
import { ActivityPoller } from "./poller";
import { DEFAULT_POLL_INTERVAL_MS, POLL_STEP_TIMEOUT_MS } from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { FiberLspSdkOptions, SdkContext, SdkEvent, SdkEventListener } from "./sdk.types";
import { describeSdkFailure, resolveSdkNetwork, runtimeTimer } from "./utils";

export class FiberLspSdk {
    private readonly context: SdkContext;

    private readonly listeners = new ListenerSet<SdkEvent>();

    /**
     * Wires the device from its seed and the host's effects; nothing connects until `connect()`.
     * @param masterSeed The 32-byte master seed; copied, so the host may discard its own.
     * @param options The network, the host's effects, the endpoints and the LSP's key.
     */
    constructor(masterSeed: Uint8Array, options: FiberLspSdkOptions) {
        assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
        if (!isPlainObject(options)) throw new TypeError("options must be an object");
        assertSdkEffects(options);
        assertNonEmptyString("rpcUrl", options.rpcUrl);
        assertNonEmptyString("signerSessionUrl", options.signerSessionUrl);
        assertCompressedPoint("lspPubkey", options.lspPubkey);
        // Not `??`: a `null` is refused below.
        const pollIntervalMs = options.pollIntervalMs === undefined ? DEFAULT_POLL_INTERVAL_MS : options.pollIntervalMs;
        assertTimerDelayMs("pollIntervalMs", pollIntervalMs, 1);
        const network = resolveSdkNetwork(options.network);
        const now = options.now ?? Date.now;
        const timer = options.timer ?? runtimeTimer();
        const store = new SignerStore(options.storage);
        const policy = new PolicyEngine(store);
        const dispatch = new SignerDispatch({ masterSeed, commitmentLock: network.commitmentLock, policy });
        // Not spread: `random` stays the session's own.
        const { connectTimeoutMs, heartbeatIntervalMs, heartbeatTimeoutMs, reconnect } = options.session ?? {};
        const session = new SignerSession({
            connectTimeoutMs,
            heartbeatIntervalMs,
            heartbeatTimeoutMs,
            reconnect,
            url: options.signerSessionUrl,
            createWebSocket: options.webSocketFactory,
            timer,
            authenticator: new WalletIdentity(masterSeed),
            handler: dispatch,
        });
        const emit = this.listeners.emit.bind(this.listeners);
        this.context = {
            network,
            lspPubkey: Uint8Array.from(options.lspPubkey),
            now,
            rpc: new FiberRpcClient({ url: options.rpcUrl, token: options.biscuitToken, fetch: options.fetch }),
            policy,
            dispatch,
            session,
            allocator: new IndexAllocator(store, now),
            activity: new ActivityTracker(store),
            poller: new ActivityPoller({ timer, intervalMs: pollIntervalMs, stepTimeoutMs: POLL_STEP_TIMEOUT_MS, steps: [], emit }),
            emit,
        };
        session.onEvent((event) => this.onSessionEvent(event));
    }

    /**
     * Reads the signer session's state.
     * @returns The state the session is in now.
     */
    get sessionState(): SessionState {
        return this.context.session.state;
    }

    /**
     * Subscribes to the events.
     * @param listener The listener; whatever it throws is swallowed.
     * @returns A function that unsubscribes it.
     */
    onEvent(listener: SdkEventListener): () => void {
        assertFunction("listener", listener);
        return this.listeners.add(listener);
    }

    /**
     * Starts polling the node and asks for the signer session, which is the host's foreground.
     * @returns Resolves once the session is established; rejects with `connect_failed` when it cannot be, the poller left running.
     */
    async connect(): Promise<void> {
        this.context.poller.start();
        try {
            await this.context.session.connect();
        } catch (cause) {
            throw new SdkError("connect_failed", describeSdkFailure("the signer session could not be established", cause), { cause });
        }
    }

    /**
     * Stops polling and closes the signer session, which is the host's background; the instance connects again on `connect()`.
     */
    disconnect(): void {
        this.context.poller.stop();
        this.context.session.disconnect();
    }

    /**
     * Forwards the session's state as `SESSION` and what goes wrong in it as `ERROR`.
     * @param event The session's event.
     */
    private onSessionEvent(event: SessionEvent): void {
        if (event.type === "state") {
            this.context.emit({ type: "SESSION", state: event.state });
            return;
        }
        const error = new SdkError("session_error", describeSdkFailure("the signer session reported an error", event.cause), {
            cause: event.cause,
        });
        this.context.emit({ type: "ERROR", error });
    }
}

/**
 * Asserts that the host's effects are callable before any is called.
 * @param options The options as the host passed them.
 */
function assertSdkEffects(options: FiberLspSdkOptions): void {
    const storage: unknown = options.storage;
    if (!isPlainObject(storage)) throw new TypeError("storage must be an object");
    assertFunction("storage.get", storage.get);
    assertFunction("storage.set", storage.set);
    assertFunction("webSocketFactory", options.webSocketFactory);
    if (options.fetch !== undefined) assertFunction("fetch", options.fetch);
    if (options.now !== undefined) assertFunction("now", options.now);
    const timer: unknown = options.timer;
    if (timer !== undefined) {
        if (!isPlainObject(timer)) throw new TypeError("timer must be an object");
        assertFunction("timer.schedule", timer.schedule);
    }
    if (options.session !== undefined && !isPlainObject(options.session)) throw new TypeError("session must be an object");
}
