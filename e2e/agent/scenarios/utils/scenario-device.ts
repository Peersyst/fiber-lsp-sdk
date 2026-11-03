import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hexToBytes } from "@noble/hashes/utils.js";
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";
import type { SdkChannelOpening, SdkEvent, SdkEventType, SigningEventOutcome, Transaction } from "@peersyst/fiber-lsp-sdk";
import { registerAgentTenant, SDK_STORE_FILE } from "../../src/agent";
import { HEX_BYTES_PATTERN } from "../../src/agent.constants";
import { loadOrCreateMasterSeed } from "../../src/agent-store";
import { OpenResultCapture } from "../../src/capturing-fetch";
import { FileSignerStorage } from "../../src/file-storage";
import { bareLowerHex, messageOf } from "../../src/agent.utils";
import { AgentJsonRpc } from "../../src/json-rpc";
import { scriptFromJson } from "../../src/open-params";
import type { DevnetEnv } from "./devnet-env";
import { FaultyFetch } from "./faulty-fetch";
import { fiberNodes, mineUntil } from "./fiber-node";
import type { FiberNodes } from "./fiber-node";
import { EVENT_TIMEOUT_MS, OPENING_TIMEOUT_MS, waitUntil } from "./wait";

export const SCENARIO_POLL_INTERVAL_MS = 1000;

// As fiber's hosted e2e funds a tenant channel and pays a tenant (`lsp-remote-signer-watchtower-preimage`, steps 04 and 14).
export const CHANNEL_FUNDING_SHANNONS = "50000000000";
export const INVOICE_AMOUNT_SHANNONS = "1000000";

export type SdkEventOf<Type extends SdkEventType> = Extract<SdkEvent, { type: Type }>;

export type RecordedEvent = {
    at: number;
    /**
     * 0 for the facade the device was created with, one more for each `reopen()`.
     */
    generation: number;
    event: SdkEvent;
};

export type SigningStep = { transition: string | null; outcome: string };

// A payment received as the channel's first, under nonceReuse "allow": the add, then the device's fulfil.
export const RECEIVED_STEPS: readonly SigningStep[] = [
    { transition: "CompleteReceivedCommitment", outcome: "signed" }, // C@2
    { transition: "SendRevokeAndAck", outcome: "signed" }, // R@2
    { transition: "SendCommitmentSigned", outcome: "warning" }, // C@2
    { transition: "CompleteReceivedRevokeAndAck", outcome: "warning" }, // R@2
    { transition: "SendCommitmentSigned", outcome: "signed" }, // C@3
    { transition: "CompleteReceivedRevokeAndAck", outcome: "signed" }, // R@3
    { transition: "CompleteReceivedCommitment", outcome: "signed" }, // C@4
    { transition: "SendRevokeAndAck", outcome: "warning" }, // R@3
];

// The opening under nonceReuse "allow": the device's commitment and the peer's, both on Commitment@1.
export const OPEN_STEPS: readonly SigningStep[] = [
    { transition: "SendCommitmentSigned", outcome: "signed" },
    { transition: "CompleteReceivedCommitment", outcome: "warning" },
];

export type ScenarioDeviceOptions = {
    /**
     * The device's own by default; pass one to share it, or to arm its faults before the device first connects.
     */
    faults?: FaultyFetch;
    pollIntervalMs?: number;
};

type EventWaiter = {
    predicate: (event: SdkEvent) => boolean;
    resolve: (event: SdkEvent) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
};

export function isSdkEvent<Type extends SdkEventType>(
    type: Type,
    match: (event: SdkEventOf<Type>) => boolean = () => true,
): (event: SdkEvent) => event is SdkEventOf<Type> {
    return (event): event is SdkEventOf<Type> => event.type === type && match(event as SdkEventOf<Type>);
}

// One step per request and outcome: the poller serves a pending request, or refuses it, again on every tick.
export function signingSteps(events: readonly RecordedEvent[], channelId: string): SigningStep[] {
    const seen = new Set<string>();
    const steps: SigningStep[] = [];
    for (const { event } of events) {
        if (event.type !== "SIGNING" || bareLowerHex(event.channelId) !== bareLowerHex(channelId)) continue;
        const key = `${event.requestId ?? "none"}:${event.outcome}`;
        if (seen.has(key)) continue;
        seen.add(key);
        steps.push({ transition: event.transition, outcome: event.outcome });
    }
    return steps;
}

export function scenarioJson(value: unknown): string {
    return JSON.stringify(value, (_key, field: unknown) => (typeof field === "bigint" ? field.toString() : field));
}

function readWitnesses(signedTx: Record<string, unknown>): Uint8Array[] {
    const { witnesses } = signedTx;
    if (!Array.isArray(witnesses)) throw new Error("sign_external_funding_tx: signed_funding_tx.witnesses must be an array");
    return witnesses.map((witness: unknown, index) => {
        if (typeof witness !== "string" || !HEX_BYTES_PATTERN.test(witness)) {
            throw new Error(`sign_external_funding_tx: signed_funding_tx.witnesses[${index}] must be 0x hex bytes`);
        }
        return hexToBytes(witness.slice(2));
    });
}

export class ScenarioDevice {
    readonly events: RecordedEvent[] = [];

    private generation = 0;

    private unsubscribe: () => void;

    private readonly waiters = new Set<EventWaiter>();

    private constructor(
        private current: FiberLspSdk,
        readonly env: DevnetEnv,
        readonly nodes: FiberNodes,
        readonly faults: FaultyFetch,
        readonly tenantId: string,
        readonly accessToken: string,
        readonly storeDir: string,
        private readonly build: () => FiberLspSdk,
        private readonly capture: OpenResultCapture,
    ) {
        this.unsubscribe = this.listen(current);
    }

    static async create(env: DevnetEnv, options: ScenarioDeviceOptions = {}): Promise<ScenarioDevice> {
        const storeDir = mkdtempSync(join(tmpdir(), "fiber-lsp-scenario-"));
        try {
            const nodes = fiberNodes(env);
            const faults = options.faults ?? new FaultyFetch();
            const capture = new OpenResultCapture(faults.fetch);
            const seed = loadOrCreateMasterSeed(storeDir);
            const registry = new AgentJsonRpc(env.node2RpcUrl, fetch);
            // Pinned from the devnet's environment, never from the node the pin is meant to hold to.
            const lspPubkey = hexToBytes(bareLowerHex(env.node2Pubkey));
            const storePath = join(storeDir, SDK_STORE_FILE);
            const build = (token?: string): FiberLspSdk =>
                new FiberLspSdk(seed, {
                    network: env.network,
                    storage: new FileSignerStorage(storePath),
                    rpcUrl: env.node2RpcUrl,
                    lspPubkey,
                    biscuitToken: token,
                    fetch: capture.fetch,
                    pollIntervalMs: options.pollIntervalMs ?? SCENARIO_POLL_INTERVAL_MS,
                    nonceReuse: "allow",
                });
            const sdk = build();
            const tenant = await registerAgentTenant(sdk, registry, env.operatorToken);
            sdk.setBiscuitToken(tenant.accessToken);
            const rebuild = (): FiberLspSdk => build(tenant.accessToken);
            const device = new ScenarioDevice(sdk, env, nodes, faults, tenant.tenantId, tenant.accessToken, storeDir, rebuild, capture);
            sdk.connect();
            return device;
        } catch (error) {
            rmSync(storeDir, { recursive: true, force: true });
            throw error;
        }
    }

    get sdk(): FiberLspSdk {
        return this.current;
    }

    // Refused while a request is in flight: two stores over one file must never both write (docs/persistence.md).
    reopen(): FiberLspSdk {
        if (this.faults.inFlight !== 0) {
            throw new Error(`reopen: the old facade still has ${this.faults.inFlight} request(s) in flight`);
        }
        this.current.disconnect();
        this.unsubscribe();
        this.generation += 1;
        const sdk = this.build();
        this.current = sdk;
        this.unsubscribe = this.listen(sdk);
        return sdk;
    }

    waitForEvent<Event extends SdkEvent>(predicate: (event: SdkEvent) => event is Event, timeoutMs?: number): Promise<Event>;
    waitForEvent(predicate: (event: SdkEvent) => boolean, timeoutMs?: number): Promise<SdkEvent>;
    waitForEvent(predicate: (event: SdkEvent) => boolean, timeoutMs: number = EVENT_TIMEOUT_MS): Promise<SdkEvent> {
        const past = this.events.find((recorded) => predicate(recorded.event));
        if (past !== undefined) return Promise.resolve(past.event);
        return new Promise((resolve, reject) => {
            const waiter: EventWaiter = {
                predicate,
                resolve,
                reject,
                timer: setTimeout(() => {
                    this.waiters.delete(waiter);
                    reject(new Error(`no matching event in ${timeoutMs} ms; seen: ${this.describeEvents()}`));
                }, timeoutMs),
            };
            this.waiters.add(waiter);
        });
    }

    waitForPaymentReceived(paymentHashHex: string, timeoutMs?: number): Promise<SdkEventOf<"PAYMENT_RECEIVED">> {
        return this.waitForEvent(
            isSdkEvent("PAYMENT_RECEIVED", (event) => bareLowerHex(event.paymentHashHex) === bareLowerHex(paymentHashHex)),
            timeoutMs,
        );
    }

    signingRecords(channelId: string, outcome?: SigningEventOutcome): RecordedEvent[] {
        return this.events.filter(
            ({ event }) =>
                event.type === "SIGNING" &&
                bareLowerHex(event.channelId) === bareLowerHex(channelId) &&
                (outcome === undefined || event.outcome === outcome),
        );
    }

    waitForSigningSteps(channelId: string, from: number, count: number, timeoutMs: number = EVENT_TIMEOUT_MS): Promise<SigningStep[]> {
        return waitUntil(
            `${count} signing steps of ${channelId}`,
            () => {
                const steps = signingSteps(this.events.slice(from), channelId);
                return Promise.resolve(steps.length >= count ? steps : undefined);
            },
            { timeoutMs },
        ).catch((error: unknown) => {
            throw new Error(`${messageOf(error)}; seen: ${this.describeEvents()}`, { cause: error });
        });
    }

    async openFundedChannel(amountShannons: string, timeoutMs: number = OPENING_TIMEOUT_MS): Promise<string> {
        const { node1 } = this.nodes;
        const userLock = scriptFromJson((await node1.nodeInfo()).defaultFundingLockScript);
        const sdk = this.current;
        let raw: Record<string, unknown> | null;
        let opening: SdkChannelOpening;
        try {
            opening = await sdk.prepareChannelOpen(amountShannons, userLock);
        } finally {
            raw = this.capture.take();
        }
        if (raw === null) throw new Error(`open_tenant_channel's result for ${opening.channelId} was not captured`);
        const rawChannelId = raw.channel_id;
        if (typeof rawChannelId !== "string" || bareLowerHex(rawChannelId) !== bareLowerHex(opening.channelId)) {
            throw new Error(`open_tenant_channel's result names channel ${String(rawChannelId)}, the SDK opened ${opening.channelId}`);
        }
        const unsignedTx = raw.unsigned_funding_tx;
        if (typeof unsignedTx !== "object" || unsignedTx === null || Array.isArray(unsignedTx)) {
            throw new Error("open_tenant_channel: unsigned_funding_tx must be an object");
        }
        const signedTx = await node1.signExternalFundingTx(unsignedTx as Record<string, unknown>, this.env.fundingPrivkey);
        // The signer only writes witnesses, which the tx hash the SDK pinned leaves out.
        const fundingTx: Transaction = { ...opening.unsignedFundingTx, witnesses: readWitnesses(signedTx) };
        await sdk.submitFundingTx(opening.channelId, fundingTx);
        await this.mineUntilReady(opening.channelId, timeoutMs);
        return opening.channelId;
    }

    async close(): Promise<void> {
        this.current.disconnect();
        this.unsubscribe();
        for (const waiter of this.waiters) {
            clearTimeout(waiter.timer);
            waiter.reject(new Error("the scenario device closed"));
        }
        this.waiters.clear();
        try {
            await this.waitForSettled();
        } finally {
            rmSync(this.storeDir, { recursive: true, force: true });
        }
    }

    // So nothing the device still does writes to the store after it.
    waitForSettled(timeoutMs: number = EVENT_TIMEOUT_MS): Promise<true> {
        return waitUntil("the device's requests to settle", () => Promise.resolve(this.faults.inFlight === 0 ? true : undefined), {
            timeoutMs,
        });
    }

    describeEvents(): string {
        return scenarioJson(this.events.map(({ generation, event }) => ({ generation, ...event })));
    }

    private async mineUntilReady(channelId: string, timeoutMs: number): Promise<void> {
        const ready = isSdkEvent("CHANNEL_READY", (event) => event.channelId === channelId);
        await mineUntil(
            this.env,
            `CHANNEL_READY of ${channelId}`,
            () => Promise.resolve(this.events.some((recorded) => ready(recorded.event)) ? true : undefined),
            timeoutMs,
        );
    }

    private listen(sdk: FiberLspSdk): () => void {
        const generation = this.generation;
        return sdk.onEvent((event) => this.record({ at: Date.now(), generation, event }));
    }

    private record(recorded: RecordedEvent): void {
        this.events.push(recorded);
        for (const waiter of this.waiters) {
            if (!waiter.predicate(recorded.event)) continue;
            clearTimeout(waiter.timer);
            this.waiters.delete(waiter);
            waiter.resolve(recorded.event);
        }
    }
}
