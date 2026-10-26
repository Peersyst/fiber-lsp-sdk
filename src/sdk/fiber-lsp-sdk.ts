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
import { SignerDispatch } from "../signer";
import { ActivityTracker } from "./activity";
import { IndexAllocator } from "./allocator";
import { ActivityPoller } from "./poller";
import { DEFAULT_POLL_INTERVAL_MS, POLL_STEP_TIMEOUT_MS } from "./sdk.constants";
import { buildChannelSigningStep } from "./signing-step";
import type { FiberLspSdkOptions, SdkContext, SdkEvent, SdkEventListener } from "./sdk.types";
import { resolveSdkNetwork, runtimeTimer } from "./utils";
import { buildWatchtowerSigningStep } from "./watchtower-step";

export class FiberLspSdk {
    private readonly context: SdkContext;

    private readonly listeners = new ListenerSet<SdkEvent>();

    /**
     * Wires the device from its seed and the host's effects; nothing connects until `connect()`.
     * @param masterSeed The 32-byte master seed, copied.
     * @param options The network, the host's effects, the node's endpoint, the LSP's key, the nonce reuse mode and the watchtower's approval.
     */
    constructor(masterSeed: Uint8Array, options: FiberLspSdkOptions) {
        assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
        if (!isPlainObject(options)) throw new TypeError("options must be an object");
        assertSdkEffects(options);
        assertNonEmptyString("rpcUrl", options.rpcUrl);
        assertCompressedPoint("lspPubkey", options.lspPubkey);
        // Not `??`: a `null` is refused below.
        const pollIntervalMs = options.pollIntervalMs === undefined ? DEFAULT_POLL_INTERVAL_MS : options.pollIntervalMs;
        assertTimerDelayMs("pollIntervalMs", pollIntervalMs, 1);
        const network = resolveSdkNetwork(options.network);
        const now = options.now ?? Date.now;
        const timer = options.timer ?? runtimeTimer();
        const store = new SignerStore(options.storage);
        const policy = new PolicyEngine(store, { nonceReuse: options.nonceReuse, watchtower: options.watchtower });
        const dispatch = new SignerDispatch({
            masterSeed,
            commitmentLock: network.commitmentLock,
            fundingLockCellDepsCount: network.fundingLockCellDepsCount,
            policy,
        });
        const emit = this.listeners.emit.bind(this.listeners);
        const rpc = new FiberRpcClient({ url: options.rpcUrl, token: options.biscuitToken, fetch: options.fetch });
        const steps = [
            buildChannelSigningStep({ rpc, store, dispatch, emit }),
            buildWatchtowerSigningStep({ rpc, store, policy, dispatch, emit }),
        ];
        this.context = {
            network,
            lspPubkey: Uint8Array.from(options.lspPubkey),
            now,
            rpc,
            policy,
            dispatch,
            allocator: new IndexAllocator(store, now),
            activity: new ActivityTracker(store),
            poller: new ActivityPoller({ timer, intervalMs: pollIntervalMs, stepTimeoutMs: POLL_STEP_TIMEOUT_MS, steps, emit }),
            emit,
        };
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
     * Starts polling the node, which is the host's foreground; calling it while polling restarts nothing.
     */
    connect(): void {
        this.context.poller.start();
    }

    /**
     * Stops polling, which is the host's background; the instance polls again on `connect()`.
     */
    disconnect(): void {
        this.context.poller.stop();
    }
}

/**
 * Asserts that the host's effects are callable before any is called.
 * @param options The host's options.
 */
function assertSdkEffects(options: FiberLspSdkOptions): void {
    const storage: unknown = options.storage;
    if (!isPlainObject(storage)) throw new TypeError("storage must be an object");
    assertFunction("storage.get", storage.get);
    assertFunction("storage.set", storage.set);
    if (options.fetch !== undefined) assertFunction("fetch", options.fetch);
    if (options.now !== undefined) assertFunction("now", options.now);
    const timer: unknown = options.timer;
    if (timer !== undefined) {
        if (!isPlainObject(timer)) throw new TypeError("timer must be an object");
        assertFunction("timer.schedule", timer.schedule);
    }
}
