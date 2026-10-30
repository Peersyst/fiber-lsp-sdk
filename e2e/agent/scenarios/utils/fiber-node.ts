import type { AgentNodeFetch, ScriptJson } from "../../src/agent.types";
import { bareLowerHex, readJsonObject } from "../../src/agent.utils";
import { jsonRpcCall } from "../../src/json-rpc";
import { readScriptJson } from "../../src/open-params";
import type { DevnetEnv } from "./devnet-env";
import { GET_CHANNEL_SIGNING_STATUS_METHOD } from "./faulty-fetch";
import { EVENT_TIMEOUT_MS, sleep, waitUntil, WaitTimeoutError } from "./wait";

// Nodes 1 and 3 run without Biscuit, so the Authorization header jsonRpcCall always writes is never read.
const NO_TOKEN = "";

// What fiber's hosted e2e pays a tenant with (`lsp-remote-signer-watchtower-preimage`, step 15).
const DEFAULT_MAX_FEE_SHANNONS = 10_000n;
const DEFAULT_TLC_EXPIRY_LIMIT_MS = 0x240c8400n;

const DEFAULT_EPOCHS = 2;

// As fiber's e2e: the funding tx reaches the pool before the epochs that confirm it are mined.
const FUNDING_SETTLE_MS = 3000;

const MINING_ROUND_MS = 30_000;

export type FiberNodeInfo = { pubkey: string; defaultFundingLockScript: ScriptJson; raw: Record<string, unknown> };

export type FiberChannel = {
    channelId: string;
    peer: string;
    stateName: string;
    isPublic: boolean;
    raw: Record<string, unknown>;
};

export type FiberChannelFilter = { peer?: string; onlyPending?: boolean };

/**
 * A `SignatureRequired` status, its ids bare lowercase hex.
 */
export type FiberPendingSigningRequest = { requestId: string; transition: string; paymentHashes: string[] };

export type FiberNewInvoice = { invoiceAddress: string; paymentHash: string; raw: Record<string, unknown> };

export type FiberInvoiceState = { invoiceAddress: string; status: string; raw: Record<string, unknown> };

export type FiberPayment = { paymentHash: string; status: string; failedError: string | null; raw: Record<string, unknown> };

export type FiberGraphChannel = {
    node1: string;
    node2: string;
    /**
     * Both ends announced their fees and expiry, which routing through the channel needs.
     */
    updatedBothWays: boolean;
    raw: Record<string, unknown>;
};

export type FiberNewInvoiceOptions = {
    amountShannons: bigint;
    currency: string;
    description?: string;
    expirySeconds?: number;
    allowTrampolineRouting?: boolean;
};

export type FiberSendPaymentOptions = { maxFeeShannons?: bigint; tlcExpiryLimitMs?: bigint };

export function toHexQuantity(value: bigint | number): string {
    return `0x${value.toString(16)}`;
}

function readString(object: Record<string, unknown>, key: string, where: string): string {
    const value = object[key];
    if (typeof value !== "string") throw new Error(`${where}.${key} must be a string`);
    return value;
}

function readBoolean(object: Record<string, unknown>, key: string, where: string): boolean {
    const value = object[key];
    if (typeof value !== "boolean") throw new Error(`${where}.${key} must be a boolean`);
    return value;
}

function readArray(object: Record<string, unknown>, key: string, where: string): unknown[] {
    const value = object[key];
    if (!Array.isArray(value)) throw new Error(`${where}.${key} must be an array`);
    return value;
}

function readChannel(value: unknown): FiberChannel {
    const raw = readJsonObject(value, "list_channels channel");
    const state = readJsonObject(raw.state, "list_channels channel.state");
    return {
        channelId: readString(raw, "channel_id", "list_channels channel"),
        peer: readString(raw, "pubkey", "list_channels channel"),
        stateName: readString(state, "state_name", "list_channels channel.state"),
        isPublic: readBoolean(raw, "is_public", "list_channels channel"),
        raw,
    };
}

function readPayment(method: string, value: unknown): FiberPayment {
    const raw = readJsonObject(value, method);
    const failedError = raw.failed_error;
    return {
        paymentHash: readString(raw, "payment_hash", method),
        status: readString(raw, "status", method),
        failedError: typeof failedError === "string" ? failedError : null,
        raw,
    };
}

function readPendingSigningRequest(result: Record<string, unknown>): FiberPendingSigningRequest | undefined {
    const status = readJsonObject(result.status, "get_channel_signing_status.status");
    if (status.type !== "SignatureRequired") return undefined;
    const { request_id: requestId, transition, settlement } = status;
    if (typeof requestId !== "string" || typeof transition !== "string") {
        throw new Error("get_channel_signing_status: a SignatureRequired status must carry request_id and transition");
    }
    const tlcs = settlement === null || settlement === undefined ? [] : readJsonObject(settlement, "status.settlement").tlcs;
    const paymentHashes = (Array.isArray(tlcs) ? tlcs : []).flatMap((tlc: unknown) => {
        const hash = readJsonObject(tlc, "status.settlement.tlcs[]").payment_hash;
        return typeof hash === "string" ? [bareLowerHex(hash)] : [];
    });
    return { requestId: bareLowerHex(requestId), transition, paymentHashes };
}

function readGraphChannel(value: unknown): FiberGraphChannel {
    const raw = readJsonObject(value, "graph_channels channel");
    const updated = (key: string): boolean => raw[key] !== undefined && raw[key] !== null;
    return {
        node1: readString(raw, "node1", "graph_channels channel"),
        node2: readString(raw, "node2", "graph_channels channel"),
        updatedBothWays: updated("update_info_of_node1") && updated("update_info_of_node2"),
        raw,
    };
}

export class FiberNode {
    constructor(
        readonly url: string,
        private readonly token: string = NO_TOKEN,
        private readonly fetch: AgentNodeFetch = globalThis.fetch,
    ) {}

    call(method: string, params: readonly unknown[] = [], token: string = this.token): Promise<unknown> {
        return jsonRpcCall(this.url, this.fetch, method, params, token);
    }

    async nodeInfo(): Promise<FiberNodeInfo> {
        const raw = readJsonObject(await this.call("node_info"), "node_info");
        return {
            pubkey: readString(raw, "pubkey", "node_info"),
            defaultFundingLockScript: readScriptJson(raw.default_funding_lock_script, "node_info.default_funding_lock_script"),
            raw,
        };
    }

    async connectPeer(address: string): Promise<void> {
        await this.call("connect_peer", [{ address }]);
    }

    async openChannel(pubkey: string, fundingShannons: bigint, isPublic: boolean): Promise<string> {
        const params = { pubkey, funding_amount: toHexQuantity(fundingShannons), public: isPublic };
        const result = readJsonObject(await this.call("open_channel", [params]), "open_channel");
        return readString(result, "temporary_channel_id", "open_channel");
    }

    async listChannels(filter: FiberChannelFilter = {}, token: string = this.token): Promise<FiberChannel[]> {
        const params = { pubkey: filter.peer, only_pending: filter.onlyPending };
        const result = readJsonObject(await this.call("list_channels", [params], token), "list_channels");
        return readArray(result, "channels", "list_channels").map(readChannel);
    }

    async newInvoice(options: FiberNewInvoiceOptions): Promise<FiberNewInvoice> {
        const params = {
            amount: toHexQuantity(options.amountShannons),
            currency: options.currency,
            description: options.description,
            expiry: options.expirySeconds === undefined ? undefined : toHexQuantity(options.expirySeconds),
            allow_trampoline_routing: options.allowTrampolineRouting,
        };
        const raw = readJsonObject(await this.call("new_invoice", [params]), "new_invoice");
        const invoice = readJsonObject(raw.invoice, "new_invoice.invoice");
        const data = readJsonObject(invoice.data, "new_invoice.invoice.data");
        return {
            invoiceAddress: readString(raw, "invoice_address", "new_invoice"),
            paymentHash: readString(data, "payment_hash", "new_invoice.invoice.data"),
            raw,
        };
    }

    async getInvoice(paymentHash: string, token: string = this.token): Promise<FiberInvoiceState> {
        const raw = readJsonObject(await this.call("get_invoice", [{ payment_hash: paymentHash }], token), "get_invoice");
        return { invoiceAddress: readString(raw, "invoice_address", "get_invoice"), status: readString(raw, "status", "get_invoice"), raw };
    }

    async sendPayment(invoice: string, options: FiberSendPaymentOptions = {}): Promise<FiberPayment> {
        const params = {
            invoice,
            max_fee_amount: toHexQuantity(options.maxFeeShannons ?? DEFAULT_MAX_FEE_SHANNONS),
            tlc_expiry_limit: toHexQuantity(options.tlcExpiryLimitMs ?? DEFAULT_TLC_EXPIRY_LIMIT_MS),
        };
        return readPayment("send_payment", await this.call("send_payment", [params]));
    }

    async getPayment(paymentHash: string, token: string = this.token): Promise<FiberPayment> {
        return readPayment("get_payment", await this.call("get_payment", [{ payment_hash: paymentHash }], token));
    }

    // Throws at once on a payment that failed, with fiber's reason, unless `Failed` is the status awaited.
    waitForPaymentStatus(paymentHash: string, status: string, timeoutMs: number = EVENT_TIMEOUT_MS): Promise<FiberPayment> {
        return waitUntil(
            `${this.url}'s payment ${paymentHash} to be ${status}`,
            async () => {
                const payment = await this.getPayment(paymentHash);
                if (payment.status === status) return payment;
                if (payment.status === "Failed") throw new Error(`${this.url}'s payment ${paymentHash} failed: ${payment.failedError}`);
                return undefined;
            },
            { timeoutMs },
        );
    }

    async graphChannels(): Promise<FiberGraphChannel[]> {
        const result = readJsonObject(await this.call("graph_channels", [{}]), "graph_channels");
        return readArray(result, "channels", "graph_channels").map(readGraphChannel);
    }

    async signExternalFundingTx(unsignedFundingTx: Record<string, unknown>, privateKey: string): Promise<Record<string, unknown>> {
        const params = { unsigned_funding_tx: unsignedFundingTx, private_key: privateKey };
        const result = readJsonObject(await this.call("sign_external_funding_tx", [params]), "sign_external_funding_tx");
        return readJsonObject(result.signed_funding_tx, "sign_external_funding_tx.signed_funding_tx");
    }

    async channelSigningStatus(channelId: string, token: string): Promise<Record<string, unknown>> {
        return readJsonObject(
            await this.call(GET_CHANNEL_SIGNING_STATUS_METHOD, [{ channel_id: channelId }], token),
            GET_CHANNEL_SIGNING_STATUS_METHOD,
        );
    }

    async pendingSigningRequest(channelId: string, token: string): Promise<FiberPendingSigningRequest | undefined> {
        return readPendingSigningRequest(await this.channelSigningStatus(channelId, token));
    }
}

export type FiberNodes = {
    node1: FiberNode;
    /**
     * The LSP, carrying the operator's token.
     */
    node2: FiberNode;
    node3: FiberNode;
};

export function fiberNodes(env: DevnetEnv): FiberNodes {
    return {
        node1: new FiberNode(env.node1RpcUrl),
        node2: new FiberNode(env.node2RpcUrl, env.operatorToken),
        node3: new FiberNode(env.node3RpcUrl),
    };
}

export async function generateEpochs(env: DevnetEnv, epochs: number = DEFAULT_EPOCHS): Promise<void> {
    await jsonRpcCall(env.ckbRpcUrl, fetch, "generate_epochs", [toHexQuantity(epochs)], NO_TOKEN);
}

export async function mineUntil<T>(env: DevnetEnv, what: string, probe: () => Promise<T | undefined>, timeoutMs: number): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    await sleep(FUNDING_SETTLE_MS);
    for (;;) {
        await generateEpochs(env);
        const left = Math.max(0, Math.min(MINING_ROUND_MS, deadline - Date.now()));
        try {
            return await waitUntil(what, probe, { timeoutMs: left });
        } catch (error) {
            if (!(error instanceof WaitTimeoutError) || Date.now() >= deadline) throw error;
        }
    }
}
