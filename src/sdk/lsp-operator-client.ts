import { assertFunction, assertNonEmptyString, isPlainObject } from "../common";
import type { LspNodeStatus, RegisterTenantParams } from "../rpc";
import { FiberRpcClient, RPC_RESPONSE_PATH, RpcResponseError, assertRpcToken } from "../rpc";
import { computeTenantId, readTenantRegistration } from "../signer";
import { WireError } from "../wire";
import { SDK_REGISTRATION_CONSUMED_ERROR, SDK_REGISTRATION_INVALID_ERRORS } from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { LspOperatorClientOptions, LspRegisteredTenant } from "./sdk.types";
import { describeSdkFailure, isFiberRefusal } from "./utils";

// The decoder's path for the field, so the refusal reads as its own.
const REGISTERED_TENANT_ID_PATH = `${RPC_RESPONSE_PATH}.result.tenant.tenant_id`;

const REGISTRATION_NODE_REFUSED = "the node refuses the registration";

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
        const { tenant, accessToken } = await this.#rpc.registerTenant(read).catch((error: unknown) => {
            throw classifyRegistrationRefusal(error);
        });
        if (tenant.tenantId !== expectedTenantId) {
            throw new RpcResponseError(
                "lsp_register_tenant",
                new WireError(REGISTERED_TENANT_ID_PATH, "is not the tenant of the registered root signer"),
            );
        }
        return { tenantId: tenant.tenantId, accessToken };
    }

    /**
     * Reads the hosted LSP's status.
     * @returns The node's public key, tenant store root and tenant counts.
     */
    async getStatus(): Promise<LspNodeStatus> {
        return this.#rpc.getLspStatus();
    }
}

/**
 * Turns fiber's refusals of a registration into the facade's errors; anything else is returned as is.
 * @param error What the call threw.
 * @returns The error to throw.
 */
function classifyRegistrationRefusal(error: unknown): unknown {
    if (isFiberRefusal(error, SDK_REGISTRATION_CONSUMED_ERROR)) {
        return new SdkError("registration_consumed", describeSdkFailure(REGISTRATION_NODE_REFUSED, error), { cause: error });
    }
    if (SDK_REGISTRATION_INVALID_ERRORS.some((answer) => isFiberRefusal(error, answer))) {
        return new SdkError("registration_invalid", describeSdkFailure(REGISTRATION_NODE_REFUSED, error), { cause: error });
    }
    return error;
}
