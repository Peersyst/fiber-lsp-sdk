import type { AgentNodeFetch } from "../../src/agent.types";

// The device the fake registers: the master seed bytes 0x01 to 0x20, its RootSigner and fiber's tenant id of it.
export const DEVICE_SEED_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
export const DEVICE_ROOT_SIGNER = "03d555b5dd0f06d5d3617bd375b3022d898284f573cd610353f3ec0a1997624f7d";
export const DEVICE_TENANT_ID = "671dd6462a060f9f121f33b41d13bc7799866b76068b0d4a0eb73df3b11810c7";

// The LSP's node id: the curve's generator.
export const LSP_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// The request ids a test's `randomBytes` draws, in order, and the signing time: the specs' clock, 2027-01-15T08:00:00Z.
export const REGISTRATION_REQUEST_ID = new Uint8Array(32).fill(0x5a);
export const RETRY_REQUEST_ID = new Uint8Array(32).fill(0x5b);
export const REGISTRATION_SIGNED_AT = "0x1a3185c5000";

// The device's RFC 6979 signatures of fiber's v2 registry payload to LSP_PUBKEY at that time, one per request id, so the fake
// checks them without a curve.
export const REGISTRATION_SIGNATURE =
    "3d39f6af29b1ae89cd7db857f332e773f38eac1d376350dda30ac84ee35dbbee14cd0081a037b71308ee5dcd0059b2081c2ac154906ab89ef928ce74ebab5969";
export const RETRY_SIGNATURE =
    "c3ba88a735b78c61ef68cbae403c287cc1deea4c341803b6e04b613f1524feb33060048857d641ffb915cf1ee033f24992a1e3dc3260937157259877cb433f44";

const SIGNATURES_BY_REQUEST_ID: Readonly<Record<string, string>> = {
    [`0x${"5a".repeat(32)}`]: REGISTRATION_SIGNATURE,
    [`0x${"5b".repeat(32)}`]: RETRY_SIGNATURE,
};

// As fiber's registry refuses a request id it has seen (d8dd6d28 `lsp/registry.rs:13`), under the code every refusal of
// `lsp_register_tenant` carries (`rpc/utils.rs:21-30`).
export const REGISTRATION_REQUEST_CONSUMED = "tenant registration request was already consumed";

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

export class FakeNode {
    readonly calls: FakeNodeCall[] = [];

    registrationFailures = 0;

    // How many registrations answer another tenant's id before one answers the device's.
    foreignRegistrations = 0;

    listChannelsFails = false;

    openAnswer: FakeNodeAnswer = { error: { code: -32000, message: "the fake node was given no opening" } };

    releaseError: string | null = null;

    beforeAnswer: (method: string) => Promise<void> = async () => undefined;

    private registrations = 0;

    private readonly consumedRequestIds = new Set<string>();

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
            case "lsp_register_tenant":
                if (this.registrationFailures > 0) {
                    this.registrationFailures--;
                    return { error: { code: -32603, message: "node is starting" } };
                }
                return this.register(firstParam(params));
            case "list_channels":
                return this.listChannelsFails
                    ? { error: { code: -32603, message: "list_channels is down" } }
                    : { result: { channels: [] } };
            case "open_channel_with_external_funding":
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
        const { root_signer_pubkey: rootSigner, request_id: requestId, signed_at: signedAt, signature } = params;
        if (
            Object.keys(params).length !== 4 ||
            rootSigner !== DEVICE_ROOT_SIGNER ||
            typeof requestId !== "string" ||
            signedAt !== REGISTRATION_SIGNED_AT ||
            signature !== SIGNATURES_BY_REQUEST_ID[requestId]
        ) {
            return { error: { code: -32000, message: "invalid tenant registration" } };
        }
        if (this.consumedRequestIds.has(requestId)) return { error: { code: -32000, message: REGISTRATION_REQUEST_CONSUMED } };
        this.consumedRequestIds.add(requestId);
        this.registrations++;
        let tenantId = DEVICE_TENANT_ID;
        if (this.foreignRegistrations > 0) {
            this.foreignRegistrations--;
            tenantId = "6666666666666666666666666666666666666666666666666666666666666666";
        }
        const tenant = {
            tenant_id: tenantId,
            root_signer_pubkey: rootSigner,
            invoice_pubkey: LSP_PUBKEY,
            channels: [],
            created_at: "0x1",
            runtime_status: "active",
        };
        return { result: { tenant, access_token: `tenant-token-${this.registrations}` } };
    }
}
