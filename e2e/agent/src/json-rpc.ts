import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { SdkTenantChallenge, SdkTenantRegistration } from "@peersyst/fiber-lsp-sdk";
import type { AgentNodeFetch } from "./agent.types";

export type AgentTenantRegistration = Pick<SdkTenantRegistration, "rootSignerPubkey" | "nonce" | "signature">;

export type AgentRegisteredTenant = { tenantId: string; accessToken: string };

// As fiber's agent: a node that never answers fails the call instead of holding the agent.
const AGENT_RPC_TIMEOUT_MS = 10_000;

const COMPRESSED_POINT_HEX_LENGTH = 66;

const HASH256_HEX_LENGTH = 64;

const SIGNATURE_LENGTH = 64;

/**
 * Tells whether a value is lowercase hex of an exact number of characters, without `0x`.
 * @param value The value.
 * @param length The number of hex characters.
 * @returns Whether it is.
 */
function isBareHex(value: unknown, length: number): value is string {
    return typeof value === "string" && value.length === length && /^[0-9a-f]*$/.test(value);
}

/**
 * Tells whether a value is 32 bytes of `0x`-prefixed lowercase hex.
 * @param value The value.
 * @returns Whether it is.
 */
function isHash256(value: unknown): value is string {
    return typeof value === "string" && value.startsWith("0x") && isBareHex(value.slice(2), HASH256_HEX_LENGTH);
}

/**
 * Reads a result, or a field of one, as an object.
 * @param method The method that returned it, for the refusal.
 * @param field What the value is, for the refusal.
 * @param value The value.
 * @returns Its fields.
 */
function readResultObject(method: string, field: string, value: unknown): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${method}: ${field} must be an object`);
    return value as Record<string, unknown>;
}

/**
 * Builds the refusal of a malformed result field.
 * @param method The method that returned it.
 * @param field The field.
 * @param shape What it must be.
 * @returns The error to throw.
 */
function malformedResult(method: string, field: string, shape: string): Error {
    return new Error(`${method}: ${field} must be ${shape}`);
}

/**
 * Asserts that bytes have an exact length before they go on the wire.
 * @param name The value, for the refusal.
 * @param bytes The bytes.
 * @param length The length they must have.
 */
function assertLength(name: string, bytes: Uint8Array, length: number): void {
    if (!(bytes instanceof Uint8Array) || bytes.length !== length) throw new TypeError(`${name} must be ${length} bytes`);
}

export class AgentJsonRpc {
    /**
     * Binds the client to a node.
     * @param url The node's JSON-RPC endpoint.
     * @param fetch How requests are sent; global `fetch` in the agent.
     */
    constructor(
        private readonly url: string,
        private readonly fetch: AgentNodeFetch,
    ) {}

    /**
     * Sends one call and reads its result, turning a transport failure, a non-2xx answer or a JSON-RPC error into a throw.
     * @param method The method.
     * @param params Its positional params: one object, or none.
     * @param token The Bearer token the call carries.
     * @returns The result.
     */
    private async call(method: string, params: readonly Record<string, string>[], token: string): Promise<unknown> {
        let response: Awaited<ReturnType<AgentNodeFetch>>;
        let text: string;
        try {
            response = await this.fetch(this.url, {
                method: "POST",
                headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
                body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
                signal: AbortSignal.timeout(AGENT_RPC_TIMEOUT_MS),
            });
            text = await response.text();
        } catch (error) {
            throw new Error(`${method}: no answer from ${this.url}: ${error instanceof Error ? error.message : String(error)}`);
        }
        if (response.status < 200 || response.status > 299) throw new Error(`${method}: HTTP ${response.status} from ${this.url}: ${text}`);
        let envelope: unknown;
        try {
            envelope = JSON.parse(text);
        } catch {
            throw new Error(`${method}: the answer from ${this.url} is not JSON`);
        }
        if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
            throw new Error(`${method}: the answer from ${this.url} is not a JSON object`);
        }
        const body = envelope as Record<string, unknown>;
        if (Object.hasOwn(body, "error")) {
            const error = body.error;
            const message = typeof error === "object" && error !== null && "message" in error ? error.message : undefined;
            throw new Error(typeof message === "string" ? message : "unknown JSON-RPC error");
        }
        if (!Object.hasOwn(body, "result")) throw new Error(`${method}: the answer from ${this.url} has neither result nor error`);
        return body.result;
    }

    /**
     * Reads the node's identity key, which is the LSP's.
     * @param operatorToken The operator's token.
     * @returns The node id, 33 bytes of lowercase hex without `0x`, as fiber writes it.
     */
    async nodeInfo(operatorToken: string): Promise<string> {
        const result = readResultObject("node_info", "the result", await this.call("node_info", [], operatorToken));
        if (!isBareHex(result.pubkey, COMPRESSED_POINT_HEX_LENGTH))
            throw malformedResult("node_info", "pubkey", "33 bytes of bare lowercase hex");
        return result.pubkey;
    }

    /**
     * Asks the LSP's registry for a nonce bound to the device's RootSigner.
     * @param rootSignerPubkeyHex The RootSigner's key, 33 bytes of lowercase hex without `0x`.
     * @param operatorToken The operator's token.
     * @returns The challenge, ready for the SDK's `signTenantRegistration`.
     */
    async getTenantRegistryNonce(rootSignerPubkeyHex: string, operatorToken: string): Promise<SdkTenantChallenge> {
        if (!isBareHex(rootSignerPubkeyHex, COMPRESSED_POINT_HEX_LENGTH))
            throw new TypeError("rootSignerPubkeyHex must be 33 bytes of bare lowercase hex");
        const method = "lsp_get_tenant_registry_nonce";
        const result = readResultObject(
            method,
            "the result",
            await this.call(method, [{ root_signer_pubkey: rootSignerPubkeyHex }], operatorToken),
        );
        const { lsp_node_id: lspNodeId, root_signer_pubkey: rootSignerPubkey, nonce } = result;
        if (!isBareHex(lspNodeId, COMPRESSED_POINT_HEX_LENGTH))
            throw malformedResult(method, "lsp_node_id", "33 bytes of bare lowercase hex");
        if (!isBareHex(rootSignerPubkey, COMPRESSED_POINT_HEX_LENGTH))
            throw malformedResult(method, "root_signer_pubkey", "33 bytes of bare lowercase hex");
        if (!isHash256(nonce)) throw malformedResult(method, "nonce", "32 bytes of 0x-prefixed lowercase hex");
        return { lspNodeId: hexToBytes(lspNodeId), rootSignerPubkey: hexToBytes(rootSignerPubkey), nonce: hexToBytes(nonce.slice(2)) };
    }

    /**
     * Registers the device's RootSigner as a tenant, with the signature the SDK made over the registry nonce.
     * @param registration The RootSigner's key, the nonce and the signature.
     * @param operatorToken The operator's token.
     * @returns The tenant id and the tenant's access token.
     */
    async registerTenant(registration: AgentTenantRegistration, operatorToken: string): Promise<AgentRegisteredTenant> {
        assertLength("rootSignerPubkey", registration.rootSignerPubkey, COMPRESSED_POINT_HEX_LENGTH / 2);
        assertLength("nonce", registration.nonce, HASH256_HEX_LENGTH / 2);
        assertLength("signature", registration.signature, SIGNATURE_LENGTH);
        const method = "lsp_register_tenant";
        const params = {
            root_signer_pubkey: bytesToHex(registration.rootSignerPubkey),
            nonce: `0x${bytesToHex(registration.nonce)}`,
            signature: bytesToHex(registration.signature),
        };
        const result = readResultObject(method, "the result", await this.call(method, [params], operatorToken));
        const tenant = readResultObject(method, "tenant", result.tenant);
        if (!isBareHex(tenant.tenant_id, HASH256_HEX_LENGTH))
            throw malformedResult(method, "tenant.tenant_id", "32 bytes of bare lowercase hex");
        if (typeof result.access_token !== "string" || result.access_token === "")
            throw malformedResult(method, "access_token", "a non-empty string");
        return { tenantId: tenant.tenant_id, accessToken: result.access_token };
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
