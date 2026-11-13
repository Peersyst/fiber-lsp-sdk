import { LspOperatorClient } from "@peersyst/fiber-lsp-sdk";
import { HASH256_HEX_LENGTH } from "./agent.constants";
import type { AgentNodeFetch } from "./agent.types";
import { isBareHex, messageOf } from "./agent.utils";

// As fiber's agent: a node that never answers fails the call instead of holding the agent.
const AGENT_RPC_TIMEOUT_MS = 10_000;

/**
 * Tells whether a value is 32 bytes of `0x`-prefixed lowercase hex.
 * @param value The value.
 * @returns Whether it is.
 */
function isHash256(value: unknown): value is string {
    return typeof value === "string" && value.startsWith("0x") && isBareHex(value.slice(2), HASH256_HEX_LENGTH);
}

/**
 * Builds the operator's client of a node, its calls abandoned after the agent's timeout.
 * @param url The node's JSON-RPC endpoint.
 * @param fetch How requests are sent.
 * @param operatorToken The operator's token.
 * @returns The client.
 */
export function agentOperatorClient(url: string, fetch: AgentNodeFetch, operatorToken: string): LspOperatorClient {
    return new LspOperatorClient({
        rpcUrl: url,
        operatorToken,
        fetch: (target, init) => fetch(target, { ...init, signal: AbortSignal.timeout(AGENT_RPC_TIMEOUT_MS) }),
    });
}

/**
 * Reads the JSON-RPC method a request body calls and the params it passes.
 * @param body The request body.
 * @returns The method, `null` when the body names none, and the params, `undefined` when it carries none.
 */
export function readJsonRpcRequest(body: string): { method: string | null; params: unknown } {
    let request: unknown;
    try {
        request = JSON.parse(body);
    } catch {
        return { method: null, params: undefined };
    }
    if (typeof request !== "object" || request === null) return { method: null, params: undefined };
    const method = "method" in request && typeof request.method === "string" ? request.method : null;
    return { method, params: "params" in request ? request.params : undefined };
}

/**
 * The token of a call to a node that reads none (a CKB RPC, a node without Biscuit): no Authorization is sent.
 */
export const NO_BEARER_TOKEN = "";

/**
 * Sends one call and reads its result, throwing on any failure.
 * @param url The node's JSON-RPC endpoint.
 * @param fetch How the request is sent.
 * @param method The method.
 * @param params Its positional params.
 * @param token The Bearer token the call carries, or NO_BEARER_TOKEN for none.
 * @returns The result.
 */
export async function jsonRpcCall(
    url: string,
    fetch: AgentNodeFetch,
    method: string,
    params: readonly unknown[],
    token: string,
): Promise<unknown> {
    let response: Awaited<ReturnType<AgentNodeFetch>>;
    let text: string;
    try {
        response = await fetch(url, {
            method: "POST",
            headers:
                token === NO_BEARER_TOKEN
                    ? { "Content-Type": "application/json" }
                    : { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
            body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
            signal: AbortSignal.timeout(AGENT_RPC_TIMEOUT_MS),
        });
        text = await response.text();
    } catch (error) {
        throw new Error(`${method}: no answer from ${url}: ${messageOf(error)}`);
    }
    if (response.status < 200 || response.status > 299) throw new Error(`${method}: HTTP ${response.status} from ${url}: ${text}`);
    let envelope: unknown;
    try {
        envelope = JSON.parse(text);
    } catch {
        throw new Error(`${method}: the answer from ${url} is not JSON`);
    }
    if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
        throw new Error(`${method}: the answer from ${url} is not a JSON object`);
    }
    const body = envelope as Record<string, unknown>;
    if (Object.hasOwn(body, "error")) {
        const error = body.error;
        const message = typeof error === "object" && error !== null && "message" in error ? error.message : undefined;
        throw new Error(typeof message === "string" ? message : "unknown JSON-RPC error");
    }
    if (!Object.hasOwn(body, "result")) throw new Error(`${method}: the answer from ${url} has neither result nor error`);
    return body.result;
}

export class AgentJsonRpc {
    /**
     * Binds the client to a node.
     * @param url The node's JSON-RPC endpoint.
     * @param fetch How requests are sent.
     */
    constructor(
        private readonly url: string,
        private readonly fetch: AgentNodeFetch,
    ) {}

    /**
     * Sends one call to the bound node.
     * @param method The method.
     * @param params Its positional params.
     * @param token The Bearer token the call carries, or NO_BEARER_TOKEN for none.
     * @returns The result.
     */
    private call(method: string, params: readonly unknown[], token: string): Promise<unknown> {
        return jsonRpcCall(this.url, this.fetch, method, params, token);
    }

    /**
     * Settles a hold invoice the node keeps for the tenant.
     * @param paymentHash The invoice's payment hash, 32 bytes of `0x`-prefixed lowercase hex.
     * @param preimage Its preimage, in the same form.
     * @param tenantToken The tenant's token.
     */
    async settleInvoice(paymentHash: string, preimage: string, tenantToken: string): Promise<void> {
        assertHash256Params(paymentHash, preimage);
        await this.call("settle_invoice", [{ payment_hash: paymentHash, payment_preimage: preimage }], tenantToken);
    }

    /**
     * Hands a preimage to the node's watchtower, for it to claim a received TLC on chain.
     * @param paymentHash The TLC's payment hash, 32 bytes of `0x`-prefixed lowercase hex.
     * @param preimage Its preimage, in the same form.
     * @param tenantToken The tenant's token.
     */
    async createPreimage(paymentHash: string, preimage: string, tenantToken: string): Promise<void> {
        assertHash256Params(paymentHash, preimage);
        await this.call("create_preimage", [{ payment_hash: paymentHash, preimage }], tenantToken);
    }
}

/**
 * Asserts that a payment hash and a preimage are in the form fiber's `Hash256` takes.
 * @param paymentHash The payment hash.
 * @param preimage The preimage.
 */
function assertHash256Params(paymentHash: string, preimage: string): void {
    if (!isHash256(paymentHash)) throw new TypeError("paymentHash must be 32 bytes of 0x-prefixed lowercase hex");
    if (!isHash256(preimage)) throw new TypeError("preimage must be 32 bytes of 0x-prefixed lowercase hex");
}
