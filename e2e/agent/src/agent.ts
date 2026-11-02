import { join } from "node:path";
import { hexToBytes } from "@noble/hashes/utils.js";
import { RpcError, SdkError } from "@peersyst/fiber-lsp-sdk";
import type { FiberLspSdk, ISignerStorage, SdkChannelOpening, SdkEvent, SdkNetworkConfig } from "@peersyst/fiber-lsp-sdk";
import { AgentRequestError } from "./agent.error";
import type {
    AgentChannel,
    AgentConfig,
    AgentEffects,
    AgentState,
    CloseAuthorization,
    FulfillmentAuthorization,
    InvoiceAuthorization,
    PaymentAuthorization,
    ReleasePreimageAuthorization,
    WatchtowerAuthorization,
} from "./agent.types";
import { agentLogger } from "./agent-log";
import type { AgentLogger } from "./agent-log";
import { loadOrCreateMasterSeed, readAgentState, writeAgentState } from "./agent-store";
import { assertPreimageMatches, preimageMatches, readAuthorization } from "./authorize";
import { OpenResultCapture, checkedOpenResult } from "./capturing-fetch";
import { CoalescingTask } from "./coalescing-task";
import { recordAgentDebitIntent } from "./debit-intent";
import { devnetNetwork } from "./devnet-network";
import { FacadeGate } from "./facade-gate";
import { FileSignerStorage, writeFileAtomically } from "./file-storage";
import { AgentJsonRpc } from "./json-rpc";
import type { AgentRegisteredTenant } from "./json-rpc";
import { messageOf, readJsonObject } from "./agent.utils";
import { NonceCapBypassStorage } from "./nonce-cap-bypass";
import { readOpenChannelRequest, readScriptJson, sameScriptJson, scriptFromJson } from "./open-params";
import { agentStatus } from "./status";
import type { AgentStatusChannel } from "./status";

export const SDK_STORE_FILE = "sdk-store.json";

export const INITIALIZE_RETRY_MS = 1000;

const REGISTRATION_REQUEST_ID_LENGTH = 32;

type AgentFacade = { sdk: FiberLspSdk; gate: FacadeGate };

/**
 * Turns an SDK refusal into a request refusal, leaving anything else as is.
 * @param error What the SDK threw.
 * @returns The error to throw.
 */
function sdkRefusal(error: unknown): unknown {
    if (error instanceof SdkError || error instanceof RpcError) return new AgentRequestError(`${error.code}: ${error.message}`);
    if (error instanceof TypeError || error instanceof RangeError) return new AgentRequestError(error.message);
    return error;
}

/**
 * Registers the device's tenant with the LSP and checks the tenant id it answers.
 * @param sdk The facade.
 * @param rpc The client of the LSP's node.
 * @param operatorToken The operator's token.
 * @param effects The clock and the randomness.
 * @returns The tenant id and the tenant's access token.
 */
export async function registerAgentTenant(
    sdk: Pick<FiberLspSdk, "tenantId" | "signTenantRegistration">,
    rpc: AgentJsonRpc,
    operatorToken: string,
    effects: Pick<AgentEffects, "now" | "randomBytes">,
): Promise<AgentRegisteredTenant> {
    // The node refuses a request id it has seen for good, so every attempt draws its own.
    const requestId = effects.randomBytes(REGISTRATION_REQUEST_ID_LENGTH);
    const registration = sdk.signTenantRegistration({ requestId, signedAtMs: BigInt(effects.now()) });
    const tenant = await rpc.registerTenant(registration, operatorToken);
    if (tenant.tenantId !== sdk.tenantId) {
        throw new Error(`lsp_register_tenant registered tenant ${tenant.tenantId}, the device is ${sdk.tenantId}`);
    }
    return tenant;
}

/**
 * Builds fiber's refusal of a payment hash already authorized under other terms.
 * @returns The error to throw.
 */
function paymentNotReplaceable(): AgentRequestError {
    return new AgentRequestError("payment authorization cannot be replaced");
}

/**
 * Tells whether two authorizations of one hash and one direction carry the same channel and terms.
 * @param a One.
 * @param b The other.
 * @returns Whether they do.
 */
function sameTerms(a: InvoiceAuthorization | PaymentAuthorization, b: InvoiceAuthorization | PaymentAuthorization): boolean {
    return (
        a.channelId === b.channelId &&
        a.hashAlgorithm === b.hashAlgorithm &&
        a.amountShannons === b.amountShannons &&
        a.expiresAtMs === b.expiresAtMs &&
        a.minTlcExpiryDeltaMs === b.minTlcExpiryDeltaMs &&
        a.maxTlcExpiryMs === b.maxTlcExpiryMs
    );
}

export class Agent {
    private readonly seed: Uint8Array;

    private readonly storage: FileSignerStorage;

    private readonly sdkStorage: ISignerStorage;

    private readonly network: SdkNetworkConfig;

    private readonly rpc: AgentJsonRpc;

    private readonly capture: OpenResultCapture;

    private readonly log: AgentLogger;

    private readonly statusWrites: CoalescingTask;

    private readonly ready: Promise<void>;

    private markReady: () => void = () => undefined;

    private state: AgentState;

    private sdk: FiberLspSdk | null = null;

    private gate: FacadeGate | null = null;

    private unsubscribe: (() => void) | null = null;

    // Control requests run one at a time, as fiber's agent reads them from one queue.
    private queue: Promise<void> = Promise.resolve();

    private stopped = false;

    /**
     * Opens the store, creating the seed on first run; nothing is sent until `start()`.
     * @param config The agent's configuration.
     * @param effects What the agent does to the outside world.
     */
    constructor(
        private readonly config: AgentConfig,
        private readonly effects: AgentEffects,
    ) {
        this.seed = loadOrCreateMasterSeed(config.storeDir);
        this.state = readAgentState(config.storeDir);
        this.storage = new FileSignerStorage(join(config.storeDir, SDK_STORE_FILE));
        this.sdkStorage = config.nonceCapBypass ? new NonceCapBypassStorage(this.storage) : this.storage;
        this.network = devnetNetwork(config.contractsDir);
        this.rpc = new AgentJsonRpc(config.rpcUrl, effects.fetch);
        this.capture = new OpenResultCapture(effects.fetch);
        this.log = agentLogger(effects.now, effects.log);
        this.statusWrites = new CoalescingTask(() => this.writeStatusFile());
        this.ready = new Promise((resolve) => (this.markReady = resolve));
    }

    /**
     * Initializes, retrying until it succeeds or the agent shuts down; control requests wait for it.
     * @returns Settles once the SDK polls or the agent shut down.
     */
    async start(): Promise<void> {
        while (!this.stopped) {
            try {
                await this.initialize();
                this.markReady();
                return;
            } catch (error) {
                this.log("initialize_failed", { error: messageOf(error) });
                await this.effects.sleep(INITIALIZE_RETRY_MS);
            }
        }
    }

    /**
     * Opens a channel to the LSP up to its unsigned funding tx, binding it once the SDK accepted the node's answer.
     * @param body The driver's body, `{ params }` in fiber's JSON.
     * @returns The node's `open_channel_with_external_funding` result, verbatim.
     */
    openChannel(body: unknown): Promise<Record<string, unknown>> {
        return this.enqueue(async () => {
            const sdk = this.activeSdk();
            const request = readOpenChannelRequest(body, this.config.lspNodeId);
            let opening: SdkChannelOpening;
            let raw: Record<string, unknown> | null;
            try {
                opening = await sdk.prepareChannelOpen(request.amountShannons, request.userLock, request.userLockCellDeps);
            } catch (error) {
                throw sdkRefusal(error);
            } finally {
                raw = this.capture.take();
            }
            const result = checkedOpenResult(raw, opening.channelId);
            const context = readJsonObject(result.opening_context, "opening_context");
            const remoteScript = readScriptJson(context.remote_shutdown_script, "opening_context.remote_shutdown_script");
            this.persist({
                ...this.state,
                channels: { ...this.state.channels, [opening.channelId]: { localScript: request.userLockJson, remoteScript } },
            });
            await this.writeStatus();
            return result;
        });
    }

    /**
     * Records or acts on one of the driver's authorizations, on a bound channel.
     * @param body The driver's body.
     * @returns `{ authorized: true }`.
     */
    async authorize(body: unknown): Promise<{ authorized: true }> {
        const authorization = readAuthorization(body);
        return this.enqueue(async () => {
            const channel = this.state.channels[authorization.channelId];
            if (channel === undefined) throw new AgentRequestError(`unknown channel ${authorization.channelId}`);
            switch (authorization.type) {
                case "Invoice":
                    this.approveInvoice(authorization);
                    break;
                case "Payment":
                    this.approvePayment(authorization);
                    break;
                case "Fulfillment":
                    this.checkFulfillment(authorization);
                    break;
                case "ReleasePreimage":
                    await this.releasePreimage(authorization);
                    break;
                case "Close":
                    this.approveClose(authorization, channel);
                    break;
                case "Watchtower":
                    await this.approveWatchtower(authorization);
                    break;
            }
            await this.writeStatus();
            return { authorized: true };
        });
    }

    /**
     * Stops polling and exits with 0.
     */
    shutdown(): void {
        this.stopped = true;
        this.sdk?.disconnect();
        this.effects.exit(0);
    }

    /**
     * Registers the tenant when the store holds no token, then builds the facade and starts it.
     */
    private async initialize(): Promise<void> {
        const facade = this.buildFacade(this.state);
        const { sdk } = facade;
        if (this.state.tenantToken === null) {
            const tenant = await registerAgentTenant(sdk, this.rpc, this.config.operatorToken, this.effects);
            this.persist({ ...this.state, tenantToken: tenant.accessToken });
            sdk.setBiscuitToken(tenant.accessToken);
        }
        this.install(facade);
        await this.writeStatus();
        if (!this.stopped) sdk.connect();
    }

    /**
     * Builds a facade from the state, behind a gate of its own.
     * @param state The state it is built from.
     * @returns The facade, not polling, and its gate.
     */
    private buildFacade(state: AgentState): AgentFacade {
        const { tenantToken, watchtower } = state;
        const gate = new FacadeGate(this.capture.fetch);
        const sdk = this.effects.createSdk(this.seed, {
            network: this.network,
            storage: this.sdkStorage,
            rpcUrl: this.config.rpcUrl,
            lspPubkey: hexToBytes(this.config.lspNodeId),
            biscuitToken: tenantToken ?? undefined,
            fetch: gate.fetch,
            now: this.effects.now,
            pollIntervalMs: this.config.intervalMs,
            nonceReuse: "allow",
            watchtower:
                watchtower === null
                    ? undefined
                    : { destination: scriptFromJson(watchtower.destination), maxFeeShannons: watchtower.maxFeeShannons },
        });
        return { sdk, gate };
    }

    /**
     * Makes a facade the running one, subscribed to its events.
     * @param facade The facade and its gate.
     */
    private install(facade: AgentFacade): void {
        this.sdk = facade.sdk;
        this.gate = facade.gate;
        this.unsubscribe = facade.sdk.onEvent((event) => this.onSdkEvent(event));
    }

    /**
     * Logs an SDK event and rewrites the status.
     * @param event The event.
     */
    private onSdkEvent(event: SdkEvent): void {
        this.log("sdk_event", event);
        void this.writeStatus();
    }

    /**
     * Approves an incoming payment, keeping its preimage for the release.
     * @param authorization The invoice.
     */
    private approveInvoice(authorization: InvoiceAuthorization): void {
        const { paymentHash } = authorization;
        const previous = this.state.invoices[paymentHash];
        // Fiber's `authorize_invoice` ends in the same `CommitmentState::authorize` as `approvePayment`.
        if (previous !== undefined && sameTerms(previous, authorization)) return;
        if (previous !== undefined || this.state.payments[paymentHash] !== undefined) throw paymentNotReplaceable();
        this.persist({ ...this.state, invoices: { ...this.state.invoices, [paymentHash]: authorization } });
    }

    /**
     * Approves an outgoing payment, recording the SDK's debit intent at its exact amount.
     * @param authorization The payment.
     */
    private approvePayment(authorization: PaymentAuthorization): void {
        const { paymentHash } = authorization;
        const previous = this.state.payments[paymentHash];
        // As fiber's `CommitmentState::authorize`: same terms are a no-op, others a refusal. Per device, not per channel as in
        // fiber: the SDK keeps one debit intent per hash.
        if (previous !== undefined && sameTerms(previous, authorization)) return;
        if (previous !== undefined || this.state.invoices[paymentHash] !== undefined) throw paymentNotReplaceable();
        recordAgentDebitIntent(this.storage, paymentHash, authorization.amountShannons);
        this.persist({ ...this.state, payments: { ...this.state.payments, [paymentHash]: authorization } });
    }

    /**
     * Checks a fulfillment as fiber's `CommitmentState::resolve` does; the SDK signs the TLC's removal under its balance rule.
     * @param authorization The fulfillment.
     */
    private checkFulfillment(authorization: FulfillmentAuthorization): void {
        const { channelId, paymentHash, preimage } = authorization;
        const payment = this.state.payments[paymentHash] ?? this.state.invoices[paymentHash];
        if (payment === undefined || payment.channelId !== channelId) throw new AgentRequestError("unknown payment");
        if (!preimageMatches(paymentHash, preimage, payment.hashAlgorithm)) {
            throw new AgentRequestError("preimage does not match payment hash");
        }
    }

    /**
     * Hands a preimage to the node once an `Invoice` authorized its hash on the channel and the preimage hashes to it.
     * @param authorization The release.
     */
    private async releasePreimage(authorization: ReleasePreimageAuthorization): Promise<void> {
        const { channelId, paymentHash, preimage, target } = authorization;
        const invoice = this.state.invoices[paymentHash];
        if (invoice === undefined || invoice.channelId !== channelId) {
            throw new AgentRequestError(`no Invoice authorization for payment hash ${paymentHash} on channel ${channelId}`);
        }
        assertPreimageMatches(paymentHash, preimage, invoice.hashAlgorithm);
        const token = this.tenantToken();
        try {
            if (target === "Invoice") await this.rpc.settleInvoice(paymentHash, preimage, token);
            else await this.rpc.createPreimage(paymentHash, preimage, token);
        } catch (error) {
            throw new AgentRequestError(messageOf(error));
        }
    }

    /**
     * Records a close once its two scripts are the channel's: the lock that funded it and the LSP's shutdown script.
     * @param authorization The close.
     * @param channel The channel it closes, as the agent bound it.
     */
    private approveClose(authorization: CloseAuthorization, channel: AgentChannel): void {
        const { channelId } = authorization;
        if (!sameScriptJson(authorization.localScript, channel.localScript)) {
            throw new AgentRequestError(`local_script must be the lock that funded channel ${channelId}`);
        }
        if (!sameScriptJson(authorization.remoteScript, channel.remoteScript)) {
            throw new AgentRequestError(`remote_script must be the LSP's shutdown script of channel ${channelId}`);
        }
        this.persist({ ...this.state, closes: { ...this.state.closes, [channelId]: authorization } });
    }

    /**
     * Records the watchtower's approval and rebuilds the facade with it, restoring the previous one on failure.
     * @param authorization The approval.
     * @returns Settles once the new facade polls.
     */
    private async approveWatchtower(authorization: WatchtowerAuthorization): Promise<void> {
        const current = this.state.watchtower;
        if (
            current !== null &&
            current.channelId !== authorization.channelId &&
            (!sameScriptJson(current.destination, authorization.destination) || current.maxFeeShannons !== authorization.maxFeeShannons)
        ) {
            throw new AgentRequestError(
                `channel ${current.channelId} approved another watchtower destination or fee cap, and the SDK takes one approval`,
            );
        }
        await this.retireFacade();
        const next = { ...this.state, watchtower: authorization };
        try {
            const facade = this.buildFacade(next);
            this.persist(next);
            this.install(facade);
        } catch (error) {
            // `persist` writes `agent.json` before it holds the state, so the state is the one the file keeps.
            this.install(this.buildFacade(this.state));
            this.connectActive();
            throw sdkRefusal(error);
        }
        this.connectActive();
    }

    /**
     * Starts the running facade's polling, unless the agent shut down.
     */
    private connectActive(): void {
        if (!this.stopped) this.activeSdk().connect();
    }

    /**
     * Stops the running facade for good: its gate refuses what it still sends, and nothing it started can still write.
     * @returns Settles once its last request was answered and what followed it ran.
     */
    private async retireFacade(): Promise<void> {
        const sdk = this.activeSdk();
        const { gate } = this;
        this.unsubscribe?.();
        this.unsubscribe = null;
        gate?.close();
        sdk.disconnect();
        await gate?.drained();
    }

    /**
     * Rewrites the status file, after the write in flight if any.
     * @returns Settles once a write that started after this call ended.
     */
    private writeStatus(): Promise<void> {
        return this.statusWrites.run();
    }

    /**
     * Writes fiber's status JSON, logging a write that fails.
     */
    private async writeStatusFile(): Promise<void> {
        const { statusFile } = this.config;
        const { sdk } = this;
        if (statusFile === null || sdk === null) return;
        try {
            const channels: AgentStatusChannel[] = [];
            for (const channelId of Object.keys(this.state.channels)) {
                channels.push({ channelId, evidence: await sdk.channelEvidence(channelId) });
            }
            const status = agentStatus({
                tenantId: sdk.tenantId,
                rootSignerPubkey: sdk.rootSignerPubkey,
                tenantToken: this.state.tenantToken,
                channels,
            });
            writeFileAtomically(statusFile, JSON.stringify(status, null, 2));
        } catch (error) {
            this.log("status_write_failed", { error });
        }
    }

    /**
     * Runs a control request once the agent is initialized and every earlier one ended.
     * @param task The request.
     * @returns What the request returns.
     */
    private enqueue<T>(task: () => Promise<T>): Promise<T> {
        const result = this.queue.then(() => this.ready).then(task);
        this.queue = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    /**
     * Writes the state to `agent.json`, then holds it.
     * @param next The state.
     */
    private persist(next: AgentState): void {
        writeAgentState(this.config.storeDir, next);
        this.state = next;
    }

    /**
     * Reads the facade the agent runs.
     * @returns The facade.
     */
    private activeSdk(): FiberLspSdk {
        if (this.sdk === null) throw new Error("the agent is not initialized");
        return this.sdk;
    }

    /**
     * Reads the tenant's token, known once initialized.
     * @returns The token.
     */
    private tenantToken(): string {
        if (this.state.tenantToken === null) throw new Error("the agent is not registered");
        return this.state.tenantToken;
    }
}
