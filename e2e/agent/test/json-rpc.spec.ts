import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AgentNodeFetch } from "../src/agent.types";
import { AgentJsonRpc } from "../src/json-rpc";

const URL = "http://127.0.0.1:21714";

const LSP_NODE_ID = "02b7ca5d4b3a7e8e5e47d16d9b0d4a8e3f1c2b3a4d5e6f708192a3b4c5d6e7f809";

const ROOT_SIGNER = "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const NONCE = "0x0101010101010101010101010101010101010101010101010101010101010101";

const SIGNATURE =
    "4444444444444444444444444444444444444444444444444444444444444444" + "5555555555555555555555555555555555555555555555555555555555555555";

const TENANT_ID = "6666666666666666666666666666666666666666666666666666666666666666";

const PAYMENT_HASH = "0x09dfb3a3e2e8e0e8a0a3d2e3b1d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f89138";

const PREIMAGE = "0x2222222222222222222222222222222222222222222222222222222222222222";

type Request = { url: string; init: Parameters<AgentNodeFetch>[1] };

function fetchAnswering(status: number, body: string): { fetch: AgentNodeFetch; requests: Request[] } {
    const requests: Request[] = [];
    const fetch: AgentNodeFetch = async (url, init) => {
        requests.push({ url, init });
        return { status, text: async () => body };
    };
    return { fetch, requests };
}

function fetchResult(result: unknown): { fetch: AgentNodeFetch; requests: Request[] } {
    return fetchAnswering(200, JSON.stringify({ jsonrpc: "2.0", result, id: 1 }));
}

function assertSent(requests: Request[], token: string, body: string): void {
    assert.equal(requests.length, 1);
    const [request] = requests;
    assert.ok(request !== undefined);
    assert.equal(request.url, URL);
    assert.equal(request.init.method, "POST");
    assert.deepEqual(request.init.headers, { "Content-Type": "application/json", Authorization: `Bearer ${token}` });
    assert.equal(request.init.body, body);
    assert.ok(request.init.signal instanceof AbortSignal);
    assert.equal(request.init.signal.aborted, false);
}

function bytes(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex.replace(/^0x/, ""), "hex"));
}

describe("AgentJsonRpc", () => {
    describe("nodeInfo", () => {
        it("sends node_info without params under the operator's token and returns the node id", async () => {
            const { fetch, requests } = fetchResult({ version: "0.9.0", pubkey: LSP_NODE_ID, addresses: [] });
            assert.equal(await new AgentJsonRpc(URL, fetch).nodeInfo("operator"), LSP_NODE_ID);
            assertSent(requests, "operator", '{"jsonrpc":"2.0","method":"node_info","params":[],"id":1}');
        });

        it("refuses a result that is not an object", async () => {
            const { fetch } = fetchResult(null);
            await assert.rejects(new AgentJsonRpc(URL, fetch).nodeInfo("operator"), { message: "node_info: the result must be an object" });
        });

        for (const [name, pubkey] of [
            ["absent", undefined],
            ["with 0x", `0x${LSP_NODE_ID}`],
            ["uppercase", LSP_NODE_ID.toUpperCase()],
            ["of 32 bytes", LSP_NODE_ID.slice(2)],
            ["of 34 bytes", `${LSP_NODE_ID}00`],
        ] as const) {
            it(`refuses a pubkey ${name}`, async () => {
                const { fetch } = fetchResult({ pubkey });
                await assert.rejects(new AgentJsonRpc(URL, fetch).nodeInfo("operator"), {
                    message: "node_info: pubkey must be 33 bytes of bare lowercase hex",
                });
            });
        }
    });

    describe("getTenantRegistryNonce", () => {
        const answer = { lsp_node_id: LSP_NODE_ID, root_signer_pubkey: ROOT_SIGNER, nonce: NONCE };

        it("sends the bare root signer key under the operator's token and returns the challenge as bytes", async () => {
            const { fetch, requests } = fetchResult(answer);
            assert.deepEqual(await new AgentJsonRpc(URL, fetch).getTenantRegistryNonce(ROOT_SIGNER, "operator"), {
                lspNodeId: bytes(LSP_NODE_ID),
                rootSignerPubkey: bytes(ROOT_SIGNER),
                nonce: bytes(NONCE),
            });
            assertSent(
                requests,
                "operator",
                `{"jsonrpc":"2.0","method":"lsp_get_tenant_registry_nonce","params":[{"root_signer_pubkey":"${ROOT_SIGNER}"}],"id":1}`,
            );
        });

        for (const [name, key] of [
            ["with 0x", `0x${ROOT_SIGNER}`],
            ["uppercase", ROOT_SIGNER.toUpperCase()],
            ["of 32 bytes", ROOT_SIGNER.slice(2)],
        ] as const) {
            it(`refuses a root signer key ${name} before sending`, async () => {
                const { fetch, requests } = fetchResult(answer);
                await assert.rejects(new AgentJsonRpc(URL, fetch).getTenantRegistryNonce(key, "operator"), {
                    message: "rootSignerPubkeyHex must be 33 bytes of bare lowercase hex",
                });
                assert.equal(requests.length, 0);
            });
        }

        const fieldCases: [keyof typeof answer, string, unknown, string][] = [
            ["lsp_node_id", "absent", undefined, "33 bytes of bare lowercase hex"],
            ["lsp_node_id", "with 0x", `0x${LSP_NODE_ID}`, "33 bytes of bare lowercase hex"],
            ["lsp_node_id", "of 32 bytes", LSP_NODE_ID.slice(2), "33 bytes of bare lowercase hex"],
            ["root_signer_pubkey", "absent", undefined, "33 bytes of bare lowercase hex"],
            ["root_signer_pubkey", "uppercase", ROOT_SIGNER.toUpperCase(), "33 bytes of bare lowercase hex"],
            ["root_signer_pubkey", "of 34 bytes", `${ROOT_SIGNER}00`, "33 bytes of bare lowercase hex"],
            ["nonce", "absent", undefined, "32 bytes of 0x-prefixed lowercase hex"],
            ["nonce", "without 0x", NONCE.slice(2), "32 bytes of 0x-prefixed lowercase hex"],
            ["nonce", "of 31 bytes", NONCE.slice(0, -2), "32 bytes of 0x-prefixed lowercase hex"],
            ["nonce", "of 33 bytes", `${NONCE}01`, "32 bytes of 0x-prefixed lowercase hex"],
        ];
        for (const [field, name, value, shape] of fieldCases) {
            it(`refuses a ${field} ${name}`, async () => {
                const { fetch } = fetchResult({ ...answer, [field]: value });
                await assert.rejects(new AgentJsonRpc(URL, fetch).getTenantRegistryNonce(ROOT_SIGNER, "operator"), {
                    message: `lsp_get_tenant_registry_nonce: ${field} must be ${shape}`,
                });
            });
        }
    });

    describe("registerTenant", () => {
        const registration = { rootSignerPubkey: bytes(ROOT_SIGNER), nonce: bytes(NONCE), signature: bytes(SIGNATURE) };
        const tenant = {
            tenant_id: TENANT_ID,
            root_signer_pubkey: ROOT_SIGNER,
            invoice_pubkey: LSP_NODE_ID,
            private_channel_id: null,
            created_at: "0x1",
            runtime_status: "Active",
            channel_online: false,
        };

        it("sends the key and signature bare and the nonce with 0x, and returns the tenant id and token", async () => {
            const { fetch, requests } = fetchResult({ tenant, access_token: "tenant-token" });
            assert.deepEqual(await new AgentJsonRpc(URL, fetch).registerTenant(registration, "operator"), {
                tenantId: TENANT_ID,
                accessToken: "tenant-token",
            });
            assertSent(
                requests,
                "operator",
                `{"jsonrpc":"2.0","method":"lsp_register_tenant","params":[{"root_signer_pubkey":"${ROOT_SIGNER}","nonce":"${NONCE}","signature":"${SIGNATURE}"}],"id":1}`,
            );
        });

        for (const [field, length] of [
            ["rootSignerPubkey", 33],
            ["nonce", 32],
            ["signature", 64],
        ] as const) {
            for (const wrong of [length - 1, length + 1]) {
                it(`refuses a ${field} of ${wrong} bytes before sending`, async () => {
                    const { fetch, requests } = fetchResult({ tenant, access_token: "tenant-token" });
                    await assert.rejects(
                        new AgentJsonRpc(URL, fetch).registerTenant({ ...registration, [field]: new Uint8Array(wrong) }, "operator"),
                        {
                            message: `${field} must be ${length} bytes`,
                        },
                    );
                    assert.equal(requests.length, 0);
                });
            }
        }

        it("refuses a result without a tenant", async () => {
            const { fetch } = fetchResult({ access_token: "tenant-token" });
            await assert.rejects(new AgentJsonRpc(URL, fetch).registerTenant(registration, "operator"), {
                message: "lsp_register_tenant: tenant must be an object",
            });
        });

        for (const [name, tenantId] of [
            ["absent", undefined],
            ["with 0x", `0x${TENANT_ID}`],
            ["uppercase", TENANT_ID.replace(/6/g, "A")],
            ["of 31 bytes", TENANT_ID.slice(2)],
        ] as const) {
            it(`refuses a tenant id ${name}`, async () => {
                const { fetch } = fetchResult({ tenant: { ...tenant, tenant_id: tenantId }, access_token: "tenant-token" });
                await assert.rejects(new AgentJsonRpc(URL, fetch).registerTenant(registration, "operator"), {
                    message: "lsp_register_tenant: tenant.tenant_id must be 32 bytes of bare lowercase hex",
                });
            });
        }

        for (const [name, token] of [
            ["absent", undefined],
            ["empty", ""],
            ["a number", 1],
        ] as const) {
            it(`refuses an access token ${name}`, async () => {
                const { fetch } = fetchResult({ tenant, access_token: token });
                await assert.rejects(new AgentJsonRpc(URL, fetch).registerTenant(registration, "operator"), {
                    message: "lsp_register_tenant: access_token must be a non-empty string",
                });
            });
        }
    });

    describe("settleInvoice", () => {
        it("sends settle_invoice with payment_preimage under the tenant's token", async () => {
            const { fetch, requests } = fetchResult({});
            assert.equal(await new AgentJsonRpc(URL, fetch).settleInvoice(PAYMENT_HASH, PREIMAGE, "tenant-token"), undefined);
            assertSent(
                requests,
                "tenant-token",
                `{"jsonrpc":"2.0","method":"settle_invoice","params":[{"payment_hash":"${PAYMENT_HASH}","payment_preimage":"${PREIMAGE}"}],"id":1}`,
            );
        });
    });

    describe("createPreimage", () => {
        it("sends create_preimage with preimage under the tenant's token", async () => {
            const { fetch, requests } = fetchResult(null);
            assert.equal(await new AgentJsonRpc(URL, fetch).createPreimage(PAYMENT_HASH, PREIMAGE, "tenant-token"), undefined);
            assertSent(
                requests,
                "tenant-token",
                `{"jsonrpc":"2.0","method":"create_preimage","params":[{"payment_hash":"${PAYMENT_HASH}","preimage":"${PREIMAGE}"}],"id":1}`,
            );
        });
    });

    for (const [method, call] of [
        ["settleInvoice", (rpc: AgentJsonRpc, hash: string, preimage: string) => rpc.settleInvoice(hash, preimage, "tenant-token")],
        ["createPreimage", (rpc: AgentJsonRpc, hash: string, preimage: string) => rpc.createPreimage(hash, preimage, "tenant-token")],
    ] as const) {
        describe(`${method} refuses before sending`, () => {
            for (const [name, value] of [
                ["without 0x", PREIMAGE.slice(2)],
                ["uppercase", PREIMAGE.replace(/2/g, "A")],
                ["of 31 bytes", PREIMAGE.slice(0, -2)],
                ["of 33 bytes", `${PREIMAGE}22`],
            ] as const) {
                it(`a payment hash ${name}`, async () => {
                    const { fetch, requests } = fetchResult({});
                    await assert.rejects(call(new AgentJsonRpc(URL, fetch), value, PREIMAGE), {
                        message: "paymentHash must be 32 bytes of 0x-prefixed lowercase hex",
                    });
                    assert.equal(requests.length, 0);
                });
                it(`a preimage ${name}`, async () => {
                    const { fetch, requests } = fetchResult({});
                    await assert.rejects(call(new AgentJsonRpc(URL, fetch), PAYMENT_HASH, value), {
                        message: "preimage must be 32 bytes of 0x-prefixed lowercase hex",
                    });
                    assert.equal(requests.length, 0);
                });
            }
        });
    }

    describe("the envelope", () => {
        const nodeInfo = (fetch: AgentNodeFetch) => new AgentJsonRpc(URL, fetch).nodeInfo("operator");

        it("throws a JSON-RPC error with the node's message", async () => {
            const { fetch } = fetchAnswering(200, '{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid tenant"},"id":1}');
            await assert.rejects(nodeInfo(fetch), { message: "Invalid tenant" });
        });

        it("throws a JSON-RPC error without a message as unknown", async () => {
            for (const error of ['{"code":-1}', '{"code":-1,"message":7}', "null", '"boom"']) {
                const { fetch } = fetchAnswering(200, `{"jsonrpc":"2.0","error":${error},"id":1}`);
                await assert.rejects(nodeInfo(fetch), { message: "unknown JSON-RPC error" });
            }
        });

        it("prefers the error over a result beside it", async () => {
            const { fetch } = fetchAnswering(
                200,
                `{"jsonrpc":"2.0","result":{"pubkey":"${LSP_NODE_ID}"},"error":{"message":"both"},"id":1}`,
            );
            await assert.rejects(nodeInfo(fetch), { message: "both" });
        });

        it("reads any 2xx status", async () => {
            for (const status of [200, 204, 299]) {
                const { fetch } = fetchAnswering(status, `{"jsonrpc":"2.0","result":{"pubkey":"${LSP_NODE_ID}"},"id":1}`);
                assert.equal(await nodeInfo(fetch), LSP_NODE_ID);
            }
        });

        it("throws a status outside 2xx with its body", async () => {
            for (const status of [199, 300, 401, 500]) {
                const { fetch } = fetchAnswering(status, "denied");
                await assert.rejects(nodeInfo(fetch), { message: `node_info: HTTP ${status} from ${URL}: denied` });
            }
        });

        it("throws a body that is not JSON", async () => {
            const { fetch } = fetchAnswering(200, "<html>");
            await assert.rejects(nodeInfo(fetch), { message: `node_info: the answer from ${URL} is not JSON` });
        });

        it("throws a JSON body that is not an object", async () => {
            for (const body of ["[]", "null", '"x"']) {
                const { fetch } = fetchAnswering(200, body);
                await assert.rejects(nodeInfo(fetch), { message: `node_info: the answer from ${URL} is not a JSON object` });
            }
        });

        it("throws an envelope with neither result nor error", async () => {
            const { fetch } = fetchAnswering(200, '{"jsonrpc":"2.0","id":1}');
            await assert.rejects(nodeInfo(fetch), { message: `node_info: the answer from ${URL} has neither result nor error` });
        });

        it("bounds every call at 10 seconds", async (t) => {
            const timeout = t.mock.method(AbortSignal, "timeout");
            const { fetch, requests } = fetchResult({ version: "0.9.0", pubkey: LSP_NODE_ID, addresses: [] });
            await nodeInfo(fetch);
            assert.deepEqual(
                timeout.mock.calls.map((call) => call.arguments),
                [[10_000]],
            );
            assert.equal(requests[0]?.init.signal, timeout.mock.calls[0]?.result);
        });

        it("throws when no answer arrives", async () => {
            const fetch: AgentNodeFetch = async () => {
                throw new TypeError("fetch failed");
            };
            await assert.rejects(nodeInfo(fetch), { message: `node_info: no answer from ${URL}: fetch failed` });
        });

        it("throws when the body cannot be read", async () => {
            const fetch: AgentNodeFetch = async () => ({
                status: 200,
                text: async () => {
                    throw new Error("socket hang up");
                },
            });
            await assert.rejects(nodeInfo(fetch), { message: `node_info: no answer from ${URL}: socket hang up` });
        });
    });
});
