import { assertFunction, assertNonEmptyString, isPlainObject } from "../common";
import type { RegisterTenantParams } from "../rpc";
import { FiberRpcClient, RPC_RESPONSE_PATH, RpcResponseError, assertRpcToken } from "../rpc";
import { computeTenantId, readTenantRegistration } from "../signer";
import { WireError } from "../wire";
import type { LspOperatorClientOptions, LspRegisteredTenant } from "./sdk.types";

// The decoder's path for the field, so the refusal reads as its own.
const REGISTERED_TENANT_ID_PATH = `${RPC_RESPONSE_PATH}.result.tenant.tenant_id`;

export class LspOperatorClient {
    readonly #rpc: FiberRpcClient;

    /**
     * Creates the operator's client of one LSP node.
     * @param options The node's url, the operator's token and an optional fetch.
     */
    constructor(options: LspOperatorClientOptions) {
        if (!isPlainObject(options)) throw new TypeError("options must be an object");
        const { rpcUrl, operatorToken, fetch } = options;
        if (fetch !== undefined) assertFunction("fetch", fetch);
        assertNonEmptyString("rpcUrl", rpcUrl);
        // Here, not in the client: it reads an absent token as none, and names it `token`.
        assertRpcToken("operatorToken", operatorToken);
        this.#rpc = new FiberRpcClient({ url: rpcUrl, token: operatorToken, fetch });
    }

    /**
     * Registers a tenant with the device's signed registration, refusing an answer that names another tenant.
     * @param registration The device's signed registration.
     * @returns The tenant id and its access token.
     */
    async registerTenant(registration: RegisterTenantParams): Promise<LspRegisteredTenant> {
        const read = readTenantRegistration(registration);
        // From the bytes the call sends, before it: a registration mutated meanwhile changes neither.
        const expectedTenantId = computeTenantId(read.rootSignerPubkey);
        const { tenant, accessToken } = await this.#rpc.registerTenant(read);
        if (tenant.tenantId !== expectedTenantId) {
            throw new RpcResponseError(
                "lsp_register_tenant",
                new WireError(REGISTERED_TENANT_ID_PATH, "is not the tenant of the registered root signer"),
            );
        }
        return { tenantId: tenant.tenantId, accessToken };
    }
}
