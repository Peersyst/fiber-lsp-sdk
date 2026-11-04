import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";
import type { SdkChannelOpening, SdkEvent, SdkEventType, SigningEventOutcome, Transaction } from "@peersyst/fiber-lsp-sdk";
import { registerAgentTenant, SDK_STORE_FILE } from "../../src/agent";
import { OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD } from "../../src/agent.constants";
import { loadOrCreateMasterSeed } from "../../src/agent-store";
import { OpenResultCapture, checkedOpenResult } from "../../src/capturing-fetch";
import { FileSignerStorage } from "../../src/file-storage";
import { NonceCapBypassStorage } from "../../src/nonce-cap-bypass";
import { bareLowerHex, messageOf } from "../../src/agent.utils";
import { ckbTxHash, readCkbTxJson } from "../../src/ckb-tx";
import { AgentJsonRpc } from "../../src/json-rpc";
import { scriptFromJson } from "../../src/open-params";
import { liveCellLockResolver, signSighashAllInputs } from "../../src/sighash-signer";
import { FaultyFetch } from "./faulty-fetch";
import { advanceChainUntil, CHANNEL_CLOSED_STATE, CHANNEL_READY_STATE, fiberNodes, settleChain } from "./fiber-node";
import type { FiberChannel, FiberNewInvoice, FiberNodes } from "./fiber-node";
import { FORCE_CLOSE_SLACK_MS, watchdogLatestMs } from "./scenario-env";
import type { ScenarioEnv } from "./scenario-env";
import { EVENT_TIMEOUT_MS, waitUntil } from "./wait";

export const SCENARIO_POLL_INTERVAL_MS = 1000;

// As fiber's hosted e2e pays a tenant (`lsp-remote-signer-watchtower-preimage`, step 14).
export const INVOICE_AMOUNT_SHANNONS = "1000000";

// As fiber's hosted tenant pays node 1 (`e2e/lsp`, steps 27 and 28).
export const OUTBOUND_AMOUNT_SHANNONS = 100_000n;
const OUTBOUND_INVOICE_EXPIRY_SECONDS = 3600;

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

// docs/signing.md's payment sent under nonceReuse "allow": the send, then the peer's fulfil up to a third session on C@3.
export const SENT_STEPS: readonly SigningStep[] = [
    { transition: "SendCommitmentSigned", outcome: "signed" }, // C@2
    { transition: "CompleteReceivedRevokeAndAck", outcome: "signed" }, // R@2
    { transition: "CompleteReceivedCommitment", outcome: "signed" }, // C@3
    { transition: "SendRevokeAndAck", outcome: "warning" }, // R@2
    { transition: "CompleteReceivedCommitment", outcome: "warning" }, // C@3
    { transition: "SendRevokeAndAck", outcome: "signed" }, // R@3
    { transition: "SendCommitmentSigned", outcome: "refused" }, // C@3, a third session
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
    nonceCapBypass?: boolean;
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

function channelSigningRecords(events: readonly RecordedEvent[], channelId: string, outcome?: SigningEventOutcome): RecordedEvent[] {
    return events.filter(
        ({ event }) =>
            event.type === "SIGNING" &&
            bareLowerHex(event.channelId) === bareLowerHex(channelId) &&
            (outcome === undefined || event.outcome === outcome),
    );
}

export function isPaymentSent(paymentHashHex: string): (event: SdkEvent) => event is SdkEventOf<"PAYMENT_SENT"> {
    return isSdkEvent("PAYMENT_SENT", (event) => bareLowerHex(event.paymentHashHex) === bareLowerHex(paymentHashHex));
}

export function isPaymentReceived(paymentHashHex: string): (event: SdkEvent) => event is SdkEventOf<"PAYMENT_RECEIVED"> {
    return isSdkEvent("PAYMENT_RECEIVED", (event) => bareLowerHex(event.paymentHashHex) === bareLowerHex(paymentHashHex));
}

function isChannelClosed(channelId: string): (event: SdkEvent) => event is SdkEventOf<"CHANNEL_CLOSED"> {
    return isSdkEvent("CHANNEL_CLOSED", (event) => bareLowerHex(event.channelId) === bareLowerHex(channelId));
}

// One step per request and outcome: the poller serves a pending request, or refuses it, again on every tick.
function firstOfEachStep(records: readonly RecordedEvent[]): { at: number; step: SigningStep }[] {
    const seen = new Set<string>();
    const steps: { at: number; step: SigningStep }[] = [];
    for (const { at, event } of records) {
        if (event.type !== "SIGNING") continue;
        const key = `${event.requestId ?? "none"}:${event.outcome}`;
        if (seen.has(key)) continue;
        seen.add(key);
        steps.push({ at, step: { transition: event.transition, outcome: event.outcome } });
    }
    return steps;
}

export function signingSteps(events: readonly RecordedEvent[], channelId: string): SigningStep[] {
    return firstOfEachStep(channelSigningRecords(events, channelId)).map(({ step }) => step);
}

export function scenarioJson(value: unknown): string {
    return JSON.stringify(value, (_key, field: unknown) => (typeof field === "bigint" ? field.toString() : field));
}

// On stderr, which the runner prints with the test, so a public chain's run leaves its txs to look up.
function noteTx(kind: "funding" | "close", channelId: string, txHash: string): void {
    process.stderr.write(`scenario ${kind} tx of ${channelId}: ${txHash}\n`);
}

export class ScenarioDevice {
    readonly events: RecordedEvent[] = [];

    private generation = 0;

    private unsubscribe: () => void;

    private readonly waiters = new Set<EventWaiter>();

    private constructor(
        private current: FiberLspSdk,
        readonly env: ScenarioEnv,
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

    static async create(env: ScenarioEnv, options: ScenarioDeviceOptions = {}): Promise<ScenarioDevice> {
        const storeDir = mkdtempSync(join(tmpdir(), "fiber-lsp-scenario-"));
        try {
            const nodes = fiberNodes(env);
            const faults = options.faults ?? new FaultyFetch();
            const capture = new OpenResultCapture(faults.fetch);
            const seed = loadOrCreateMasterSeed(storeDir);
            const registry = new AgentJsonRpc(env.node2RpcUrl, fetch);
            // Pinned from the scenarios' environment, never from the node the pin is meant to hold to.
            const lspPubkey = hexToBytes(bareLowerHex(env.node2Pubkey));
            const storePath = join(storeDir, SDK_STORE_FILE);
            const build = (token?: string): FiberLspSdk => {
                const storage = new FileSignerStorage(storePath);
                return new FiberLspSdk(seed, {
                    network: env.sdkNetwork,
                    storage: options.nonceCapBypass === true ? new NonceCapBypassStorage(storage) : storage,
                    rpcUrl: env.node2RpcUrl,
                    lspPubkey,
                    biscuitToken: token,
                    fetch: capture.fetch,
                    pollIntervalMs: options.pollIntervalMs ?? SCENARIO_POLL_INTERVAL_MS,
                    nonceReuse: "allow",
                });
            };
            const sdk = build();
            const tenant = await registerAgentTenant(sdk, registry, env.operatorToken, { now: Date.now, randomBytes });
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
        return this.waitForEvent(isPaymentReceived(paymentHashHex), timeoutMs);
    }

    signingRecords(channelId: string, outcome?: SigningEventOutcome): RecordedEvent[] {
        return channelSigningRecords(this.events, channelId, outcome);
    }

    signingStepTimes(channelId: string, from: number): string {
        const steps = firstOfEachStep(channelSigningRecords(this.events.slice(from), channelId));
        const first = steps[0]?.at ?? 0;
        return steps.map(({ at, step }) => `${step.transition ?? "none"}:${at - first}`).join(", ");
    }

    nodeOneInvoice(description: string): Promise<FiberNewInvoice> {
        return this.nodes.node1.newInvoice({
            amountShannons: OUTBOUND_AMOUNT_SHANNONS,
            currency: this.env.chain.invoiceCurrency,
            description,
            expirySeconds: OUTBOUND_INVOICE_EXPIRY_SECONDS,
            allowTrampolineRouting: true,
        });
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

    async openFundedChannel(): Promise<string> {
        const { node1 } = this.nodes;
        const userLock = scriptFromJson((await node1.nodeInfo()).defaultFundingLockScript);
        const timeoutMs = this.env.chain.openingTimeoutMs;
        const deadline = Date.now() + timeoutMs;
        await settleChain(this.env, timeoutMs);
        const sdk = this.current;
        let raw: Record<string, unknown> | null;
        let opening: SdkChannelOpening;
        try {
            opening = await sdk.prepareChannelOpen(this.env.chain.tenantChannelShannons, userLock);
        } finally {
            raw = this.capture.take();
        }
        const unsignedTx = readCkbTxJson(
            checkedOpenResult(raw, opening.channelId).unsigned_funding_tx,
            `${OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD}.unsigned_funding_tx`,
        );
        const signedTx = await signSighashAllInputs(unsignedTx, this.env.fundingPrivkey, liveCellLockResolver(this.env.ckbRpcUrl, fetch));
        // The signer only writes witnesses, which the tx hash the SDK pinned leaves out.
        const witnesses = signedTx.witnesses.map((witness) => hexToBytes(witness.slice(2)));
        const fundingTx: Transaction = { ...opening.unsignedFundingTx, witnesses };
        await sdk.submitFundingTx(opening.channelId, fundingTx);
        noteTx("funding", opening.channelId, `0x${bytesToHex(ckbTxHash(unsignedTx))}`);
        await this.untilReady(opening.channelId, Math.max(0, deadline - Date.now()));
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

    async fiberChannel(channelId: string): Promise<FiberChannel | undefined> {
        const channels = await this.nodes.node2.listChannels({ includeClosed: true }, this.accessToken);
        return channels.find((channel) => bareLowerHex(channel.channelId) === bareLowerHex(channelId));
    }

    async waitForForceClose(
        channelId: string,
        timeoutMs: number = watchdogLatestMs(this.env.chain) + FORCE_CLOSE_SLACK_MS,
    ): Promise<{ channel: FiberChannel; at: number }> {
        const channel = await waitUntil(
            `fiber#1701 to force-close ${channelId}`,
            async () => {
                const listed = await this.fiberChannel(channelId);
                return listed !== undefined && listed.stateName !== CHANNEL_READY_STATE ? listed : undefined;
            },
            { timeoutMs },
        );
        return { channel, at: Date.now() };
    }

    // Up to the commitment's confirmation, never to its settlement past the commitment delay.
    async confirmForceClose(channelId: string): Promise<FiberChannel> {
        const closedEvent = isChannelClosed(channelId);
        await advanceChainUntil(
            this.env,
            `CHANNEL_CLOSED of ${channelId}`,
            () => Promise.resolve(this.events.some(({ event }) => closedEvent(event)) ? true : undefined),
            this.env.chain.openingTimeoutMs,
        );
        const closed = await this.fiberChannel(channelId);
        if (closed === undefined) assert.fail(`the tenant's listing lost the closed channel ${channelId}`);
        assert.equal(closed.stateName, CHANNEL_CLOSED_STATE, "the tenant's channel once its close confirmed");
        const closeTx = closed.raw.shutdown_transaction_hash;
        noteTx("close", channelId, typeof closeTx === "string" ? closeTx : "none listed");
        // Only the tenant's side runs #1701's check: the LSP's has the tenant for an internal peer, exempt (d8dd6d28
        // `fiber/channel.rs:4638-4641,6760-6769`).
        assert.ok(
            closed.stateFlags.includes("UNCOOPERATIVE_LOCAL"),
            `the tenant's side closed it uncooperatively, its flags are ${closed.stateFlags.join("|")}`,
        );
        return closed;
    }

    describeEvents(): string {
        return scenarioJson(this.events.map(({ generation, event }) => ({ generation, ...event })));
    }

    private async untilReady(channelId: string, timeoutMs: number): Promise<void> {
        const ready = isSdkEvent("CHANNEL_READY", (event) => event.channelId === channelId);
        const closed = isChannelClosed(channelId);
        await advanceChainUntil(
            this.env,
            `CHANNEL_READY of ${channelId}`,
            () => {
                if (this.events.some((recorded) => closed(recorded.event))) {
                    throw new Error(`the opening of ${channelId} closed before it was ready; seen: ${this.describeEvents()}`);
                }
                return Promise.resolve(this.events.some((recorded) => ready(recorded.event)) ? true : undefined);
            },
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
