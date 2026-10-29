import type { AgentNodeFetch } from "../../src/agent.types";

// The device the fake registers: the master seed bytes 0x01 to 0x20, its RootSigner and fiber's tenant id of it.
export const DEVICE_SEED_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
export const DEVICE_ROOT_SIGNER = "03d555b5dd0f06d5d3617bd375b3022d898284f573cd610353f3ec0a1997624f7d";
export const DEVICE_TENANT_ID = "671dd6462a060f9f121f33b41d13bc7799866b76068b0d4a0eb73df3b11810c7";

// The LSP's node id: the curve's generator.
export const LSP_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

export const REGISTRY_NONCE = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

// The device's RFC 6979 signature of the registry digest over that nonce, so the fake checks it without a curve.
export const REGISTRATION_SIGNATURE =
    "7dc0bd212b90c22602b03d013149fec03696e3d03624c92f272461d9ac5cde5f34be000f7696b1004e4c7acf67e5e899b016db1c580736366e32f32f3149bd90";

export type FakeNodeCall = { method: string; params: unknown; authorization: string | null };

export type FakeNodeAnswer = { result: unknown } | { error: { code: number; message: string } };

// The SDK writes `authorization`, the agent `Authorization`.
function header(headers: Record<string, string>, name: string): string | null {
    const found = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
    return found === undefined ? null : found[1];
}

function firstParam(params: unknown): Record<string, unknown> {
    const [first] = Array.isArray(params) ? params : [];
    return typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {};
}

// Only what registration, an idle poll and the preimage releases call.
export class FakeNode {
    readonly calls: FakeNodeCall[] = [];

    // How many `node_info` calls fail before one answers.
    nodeInfoFailures = 0;

    // How many registrations answer another tenant's id before one answers the device's.
    foreignRegistrations = 0;

    listChannelsFails = false;

    openAnswer: FakeNodeAnswer = { error: { code: -32000, message: "the fake node was given no opening" } };

    releaseError: string | null = null;

    // Awaited before a call is answered, to hold it.
    beforeAnswer: (method: string) => Promise<void> = async () => undefined;

    private registrations = 0;

    readonly fetch: AgentNodeFetch = async (_url, init) => {
        const request = JSON.parse(init.body) as { method: string; params: unknown; id: unknown };
        this.calls.push({ method: request.method, params: request.params, authorization: header(init.headers, "authorization") });
        await this.beforeAnswer(request.method);
        const answer = this.answer(request.method, request.params);
        return { status: 200, text: async () => JSON.stringify({ jsonrpc: "2.0", id: request.id, ...answer }) };
    };

    callsOf(method: string): FakeNodeCall[] {
        return this.calls.filter((call) => call.method === method);
    }

    private answer(method: string, params: unknown): FakeNodeAnswer {
        switch (method) {
            case "node_info":
                if (this.nodeInfoFailures > 0) {
                    this.nodeInfoFailures--;
                    return { error: { code: -32603, message: "node is starting" } };
                }
                return { result: { version: "0.9.0", pubkey: LSP_PUBKEY, addresses: [] } };
            case "lsp_get_tenant_registry_nonce":
                return {
                    result: { lsp_node_id: LSP_PUBKEY, root_signer_pubkey: firstParam(params).root_signer_pubkey, nonce: REGISTRY_NONCE },
                };
            case "lsp_register_tenant":
                return this.register(firstParam(params));
            case "list_channels":
                return this.listChannelsFails
                    ? { error: { code: -32603, message: "list_channels is down" } }
                    : { result: { channels: [] } };
            case "open_tenant_channel":
                return structuredClone(this.openAnswer);
            case "settle_invoice":
                return this.releaseError === null ? { result: {} } : { error: { code: -32000, message: this.releaseError } };
            case "create_preimage":
                return this.releaseError === null ? { result: null } : { error: { code: -32000, message: this.releaseError } };
            default:
                return { error: { code: -32601, message: `the fake node does not serve ${method}` } };
        }
    }

    private register(params: Record<string, unknown>): FakeNodeAnswer {
        const { root_signer_pubkey: rootSigner, nonce, signature } = params;
        if (rootSigner !== DEVICE_ROOT_SIGNER || nonce !== REGISTRY_NONCE || signature !== REGISTRATION_SIGNATURE) {
            return { error: { code: -32602, message: "invalid tenant registration" } };
        }
        this.registrations++;
        let tenantId = DEVICE_TENANT_ID;
        if (this.foreignRegistrations > 0) {
            this.foreignRegistrations--;
            tenantId = "6666666666666666666666666666666666666666666666666666666666666666";
        }
        return { result: { tenant: { tenant_id: tenantId }, access_token: `tenant-token-${this.registrations}` } };
    }
}
