import { equalBytes } from "@noble/curves/utils.js";
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
import { SignerDispatch, TenantIdentity } from "../signer";
import { ActivityTracker } from "./activity";
import { IndexAllocator } from "./allocator";
import { readSdkChannelEvidence } from "./channel-evidence";
import { ActivityPoller } from "./poller";
import { DEFAULT_POLL_INTERVAL_MS, POLL_STEP_TIMEOUT_MS } from "./sdk.constants";
import { buildChannelSigningStep } from "./signing-step";
import type {
    FiberLspSdkOptions,
    SdkChannelEvidence,
    SdkContext,
    SdkEvent,
    SdkEventListener,
    SdkTenantChallenge,
    SdkTenantRegistration,
} from "./sdk.types";
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
            millisecondsPerEpoch: network.millisecondsPerEpoch,
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
            store,
            identity: new TenantIdentity(masterSeed),
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
     * The tenant id fiber derives from the device's RootSigner.
     * @returns The 64-character lowercase hex id.
     */
    get tenantId(): string {
        return this.context.identity.tenantId;
    }

    /**
     * The RootSigner's public key, which the host asks the LSP's registry nonce for.
     * @returns A copy of the 33-byte compressed key.
     */
    get rootSignerPubkey(): Uint8Array {
        return this.context.identity.publicKey;
    }

    /**
     * Signs the LSP's registry nonce, refusing one issued by another LSP or to another RootSigner; the host makes both calls.
     * @param challenge The result of `lsp_get_tenant_registry_nonce`.
     * @returns The params of `lsp_register_tenant`, copies, with the tenant id they register.
     */
    signTenantRegistration(challenge: SdkTenantChallenge): SdkTenantRegistration {
        if (!isPlainObject(challenge)) throw new TypeError("challenge must be an object");
        assertCompressedPoint("challenge.lspNodeId", challenge.lspNodeId);
        if (!equalBytes(challenge.lspNodeId, this.context.lspPubkey)) {
            throw new TypeError("challenge.lspNodeId must be lspPubkey: the nonce was issued by another LSP");
        }
        const { identity } = this.context;
        return { ...identity.signRegistration(challenge), tenantId: identity.tenantId };
    }

    /**
     * Replaces the Biscuit token the node's calls carry, from the next one on; a refused token leaves the previous one.
     * @param token The tenant's token.
     */
    setBiscuitToken(token: string): void {
        this.context.rpc.setToken(token);
    }

    /**
     * Reads what the device keeps of a channel: its revocations, each view's last commitment and the watchtower's signatures.
     * @param channelId The channel, under any name the node gave it.
     * @returns A copy of the evidence.
     */
    channelEvidence(channelId: string): Promise<SdkChannelEvidence> {
        return readSdkChannelEvidence(this.context.store, channelId);
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
