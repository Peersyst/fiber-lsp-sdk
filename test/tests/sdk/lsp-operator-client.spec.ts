import { inspect } from "node:util";
import { hexToBytes } from "@noble/hashes/utils.js";
import type { FetchInit, IFetchLike, RegisterTenantParams } from "../../../src/rpc";
import { RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import { LspOperatorClient } from "../../../src/sdk";
import type { LspOperatorClientOptions, SdkTenantRegistration } from "../../../src/sdk";
import { WireError } from "../../../src/wire";
import { FetchMock, rpcResultAnswer } from "../../mocks/rpc";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { refusalOf } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import { answering, refusing } from "../../utils/rpc-answers";
import { toRegisterTenantParams } from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { withRuntime } from "../../utils/with-runtime";

const { lsp_register_tenant: register } = loadRpcVectors().methods;
const registry = loadInteropVectors().tenant_registry;

const RPC_URL = "http://lsp.example:8227";
const OPERATOR_TOKEN = "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiDs-operator_example=";

// The "signed payload" root signer's tenant, which both vector results name.
const TENANT_ID = "dce4e62aaaca7309671a17463fc7972b3ac4f1a0532c1eae094346b432553c81";

const SIGNED_BODY =
    '{"jsonrpc":"2.0","id":1,"method":"lsp_register_tenant","params":[{' +
    '"root_signer_pubkey":"02fb489d07e12cd0d9373b8945d0905babd24f09065f522bf8c444d19cd740392b",' +
    '"request_id":"0x19a44fe40e562e91e11756589628cd2d9c96bdf1fbc4ecdeb91ab6516266fc03",' +
    '"signed_at":"0x191dd9dec00",' +
    '"signature":"68af9e0b5ab50ae2932e92016acbce692d2101d902b718f3e4d37f31dfb5df99709727b3febfb61c5cceeb2c71f0a77cb4be281b4323724f5c2b29d88f6cba52"' +
    "}]}";

const SIGNED = caseOf(register.params, "signed payload");
const COLD = caseOf(register.results, "cold tenant without a channel").json as { tenant: Record<string, unknown>; access_token: string };

function signedRegistration(): RegisterTenantParams {
    return toRegisterTenantParams(SIGNED.values);
}

function coldNaming(tenantId: string): unknown {
    return { ...COLD, tenant: { ...COLD.tenant, tenant_id: tenantId } };
}

function clientOf(mock: FetchMock): LspOperatorClient {
    return new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN, fetch: mock.fetch });
}

function fetchRunning(mock: FetchMock, meanwhile: () => void): IFetchLike {
    return async (url: string, init: FetchInit) => {
        const answer = mock.fetch(url, init);
        meanwhile();
        return answer;
    };
}

describe("LspOperatorClient", () => {
    describe("construction", () => {
        it.each<[string, unknown, string]>([
            ["undefined", undefined, "options must be an object"],
            ["null", null, "options must be an object"],
            ["a string", RPC_URL, "options must be an object"],
            ["an array", [RPC_URL, OPERATOR_TOKEN], "options must be an object"],
        ])("refuses options that are %s", (_, options, message) => {
            expect(() => new LspOperatorClient(options as LspOperatorClientOptions)).toThrow(new TypeError(message));
        });

        it.each<[string, Record<string, unknown>, string]>([
            ["no rpcUrl", { operatorToken: OPERATOR_TOKEN }, "rpcUrl must be a non-empty string"],
            ["an empty rpcUrl", { rpcUrl: "", operatorToken: OPERATOR_TOKEN }, "rpcUrl must be a non-empty string"],
            ["an rpcUrl that is not a string", { rpcUrl: 8227, operatorToken: OPERATOR_TOKEN }, "rpcUrl must be a non-empty string"],
            ["a null rpcUrl", { rpcUrl: null, operatorToken: OPERATOR_TOKEN }, "rpcUrl must be a non-empty string"],
            ["no operatorToken", { rpcUrl: RPC_URL }, "operatorToken must be printable ASCII without spaces"],
            ["an empty operatorToken", { rpcUrl: RPC_URL, operatorToken: "" }, "operatorToken must be printable ASCII without spaces"],
            [
                "an operatorToken with a space",
                { rpcUrl: RPC_URL, operatorToken: "abc def" },
                "operatorToken must be printable ASCII without spaces",
            ],
            [
                "an operatorToken with the delete character",
                { rpcUrl: RPC_URL, operatorToken: "abc\x7f" },
                "operatorToken must be printable ASCII without spaces",
            ],
            ["a null operatorToken", { rpcUrl: RPC_URL, operatorToken: null }, "operatorToken must be printable ASCII without spaces"],
            [
                "an operatorToken that is not a string",
                { rpcUrl: RPC_URL, operatorToken: 12345 },
                "operatorToken must be printable ASCII without spaces",
            ],
            [
                "a fetch that is not a function",
                { rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN, fetch: "fetch" },
                "fetch must be a function",
            ],
            ["a null fetch", { rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN, fetch: null }, "fetch must be a function"],
        ])("refuses %s", (_, options, message) => {
            const mock = new FetchMock();
            expect(() => new LspOperatorClient({ fetch: mock.fetch, ...options } as LspOperatorClientOptions)).toThrow(
                new TypeError(message),
            );
        });

        it("refuses a token of the operator without echoing it", () => {
            const error = refusalOf(
                TypeError,
                () => new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: "secret token", fetch: new FetchMock().fetch }),
            );
            expect(error.message).toBe("operatorToken must be printable ASCII without spaces");
        });

        it("holds the operator's token in no own property, nor in any serialization of the client", () => {
            const client = clientOf(new FetchMock());
            expect(Object.keys(client)).toEqual([]);
            expect(Reflect.ownKeys(client)).toEqual([]);
            expect(JSON.stringify(client)).not.toContain(OPERATOR_TOKEN);
            expect(inspect(client, { depth: null })).not.toContain(OPERATOR_TOKEN);
        });

        it("defaults to the runtime's fetch, read at construction and called without a receiver", async () => {
            const runtime = answering(COLD);
            const client = withRuntime(
                { fetch: runtime.fetch },
                () => new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN }),
            );
            await client.registerTenant(signedRegistration());
            expect(runtime.requests).toHaveLength(1);
            expect(runtime.last.url).toBe(RPC_URL);
            expect(runtime.last.receiver).toBeUndefined();
        });

        it("prefers the host's fetch over the runtime's", async () => {
            const runtime = new FetchMock();
            const host = answering(COLD);
            const client = withRuntime({ fetch: runtime.fetch }, () => clientOf(host));
            await client.registerTenant(signedRegistration());
            expect(host.requests).toHaveLength(1);
            expect(runtime.requests).toHaveLength(0);
        });

        it.each([
            ["no fetch", undefined],
            ["a fetch that is not a function", {}],
        ])("refuses to default when the runtime has %s", (_, runtimeFetch) => {
            expect(() =>
                withRuntime({ fetch: runtimeFetch }, () => new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN })),
            ).toThrow(new TypeError("this runtime has no fetch: pass one in the options"));
        });
    });

    describe("registerTenant", () => {
        it("posts lsp_register_tenant once to the url, with the operator's token and the params in fiber's forms", async () => {
            const mock = answering(COLD);
            await clientOf(mock).registerTenant(signedRegistration());
            expect(mock.requests).toHaveLength(1);
            expect(mock.last.url).toBe(RPC_URL);
            expect(mock.last.init).toEqual({
                method: "POST",
                headers: { "content-type": "application/json", authorization: `Bearer ${OPERATOR_TOKEN}` },
                body: SIGNED_BODY,
            });
        });

        it("sends a token of the bounds of printable ASCII as it is", async () => {
            const mock = answering(COLD);
            await new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: "!~", fetch: mock.fetch }).registerTenant(signedRegistration());
            expect(mock.last.init.headers.authorization).toBe("Bearer !~");
        });

        it.each([
            ["cold tenant without a channel", "tenant-access-token-cold"],
            ["active tenant with a ckb and a udt channel", "tenant-access-token-active"],
        ])("answers the %s result with the tenant id and the access token alone", async (name, accessToken) => {
            const mock = answering(caseOf(register.results, name).json);
            const registered = await clientOf(mock).registerTenant(signedRegistration());
            expect(registered).toStrictEqual({ tenantId: TENANT_ID, accessToken });
            expect(Object.keys(registered)).toEqual(["tenantId", "accessToken"]);
        });

        it("registers the vector's signed registration of the device's root signer", async () => {
            const mock = answering(coldNaming(registry.tenant_id));
            const registration: RegisterTenantParams = {
                rootSignerPubkey: hexToBytes(registry.root_signer_pubkey),
                requestId: hexToBytes(registry.request_id),
                signedAtMs: BigInt(registry.signed_at),
                signature: hexToBytes(registry.signature),
            };
            await expect(clientOf(mock).registerTenant(registration)).resolves.toStrictEqual({
                tenantId: "a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f",
                accessToken: "tenant-access-token-cold",
            });
        });

        it("registers the facade's own output, sending the registration without its tenant id", async () => {
            const mock = answering(COLD);
            const registration: SdkTenantRegistration = { ...signedRegistration(), tenantId: TENANT_ID };
            await expect(clientOf(mock).registerTenant(registration)).resolves.toStrictEqual({
                tenantId: TENANT_ID,
                accessToken: "tenant-access-token-cold",
            });
            expect(mock.last.init.body).toBe(SIGNED_BODY);
        });

        it("numbers each call of one client", async () => {
            const mock = answering(COLD).answer(rpcResultAnswer(2, COLD));
            const client = clientOf(mock);
            await client.registerTenant(signedRegistration());
            await client.registerTenant(signedRegistration());
            expect(mock.requests.map((request) => (JSON.parse(request.init.body) as { id: number }).id)).toEqual([1, 2]);
        });

        it.each([
            ["of another root signer", "a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f"],
            ["differing in its last byte", "dce4e62aaaca7309671a17463fc7972b3ac4f1a0532c1eae094346b432553c80"],
            ["differing in its first byte", "cce4e62aaaca7309671a17463fc7972b3ac4f1a0532c1eae094346b432553c81"],
        ])("refuses an answer naming a tenant %s", async (_, tenantId) => {
            const error = await rejection(clientOf(answering(coldNaming(tenantId))).registerTenant(signedRegistration()));
            expect(error).toBeInstanceOf(RpcResponseError);
            expect(error).toMatchObject({
                name: "RpcResponseError",
                method: "lsp_register_tenant",
                path: "response.result.tenant.tenant_id",
                reason: "is not the tenant of the registered root signer",
                message: "lsp_register_tenant: response.result.tenant.tenant_id is not the tenant of the registered root signer",
            });
            expect((error as RpcResponseError).cause).toBeInstanceOf(WireError);
        });

        it("checks the answer against the key read before the call, not one put in the registration meanwhile", async () => {
            const mock = answering(COLD);
            const registration = signedRegistration();
            const fetch = fetchRunning(mock, () => {
                registration.rootSignerPubkey = hexToBytes(registry.root_signer_pubkey);
            });
            const client = new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN, fetch });
            await expect(client.registerTenant(registration)).resolves.toStrictEqual({
                tenantId: TENANT_ID,
                accessToken: "tenant-access-token-cold",
            });
        });

        it("checks the answer against the key's bytes as sent, not as overwritten meanwhile", async () => {
            const mock = answering(COLD);
            const registration = signedRegistration();
            const fetch = fetchRunning(mock, () => registration.rootSignerPubkey.set(hexToBytes(registry.root_signer_pubkey)));
            const client = new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN, fetch });
            await expect(client.registerTenant(registration)).resolves.toStrictEqual({
                tenantId: TENANT_ID,
                accessToken: "tenant-access-token-cold",
            });
        });

        it("refuses the tenant of a key put in the registration meanwhile", async () => {
            const mock = answering(coldNaming(registry.tenant_id));
            const registration = signedRegistration();
            const fetch = fetchRunning(mock, () => {
                registration.rootSignerPubkey = hexToBytes(registry.root_signer_pubkey);
            });
            const client = new LspOperatorClient({ rpcUrl: RPC_URL, operatorToken: OPERATOR_TOKEN, fetch });
            await expect(client.registerTenant(registration)).rejects.toMatchObject({
                name: "RpcResponseError",
                path: "response.result.tenant.tenant_id",
                reason: "is not the tenant of the registered root signer",
            });
        });

        it("reads each member of the registration once", async () => {
            const signed = signedRegistration();
            const reads: string[] = [];
            const registration = {
                get rootSignerPubkey(): Uint8Array {
                    reads.push("rootSignerPubkey");
                    return signed.rootSignerPubkey;
                },
                get requestId(): Uint8Array {
                    reads.push("requestId");
                    return signed.requestId;
                },
                get signedAtMs(): bigint {
                    reads.push("signedAtMs");
                    return signed.signedAtMs;
                },
                get signature(): Uint8Array {
                    reads.push("signature");
                    return signed.signature;
                },
            };
            const mock = answering(COLD);
            await clientOf(mock).registerTenant(registration);
            expect(reads).toEqual(["rootSignerPubkey", "requestId", "signedAtMs", "signature"]);
            expect(mock.last.init.body).toBe(SIGNED_BODY);
        });

        it("surfaces the node's refusal as an RpcError", async () => {
            const error = await rejection(
                clientOf(refusing(-32000, "tenant registration request was already consumed")).registerTenant(signedRegistration()),
            );
            expect(error).toBeInstanceOf(RpcError);
            expect(error).toMatchObject({
                method: "lsp_register_tenant",
                code: -32000,
                message: "tenant registration request was already consumed",
            });
        });

        it("surfaces a fetch that throws as an RpcTransportError carrying the cause", async () => {
            const cause = new Error("connection refused");
            const error = await rejection(clientOf(new FetchMock().answer({ rejection: cause })).registerTenant(signedRegistration()));
            expect(error).toBeInstanceOf(RpcTransportError);
            expect(error).toMatchObject({
                method: "lsp_register_tenant",
                message: "lsp_register_tenant: the request failed",
                status: undefined,
            });
            expect((error as RpcTransportError).cause).toBe(cause);
        });

        it("surfaces a status out of 2xx as an RpcTransportError", async () => {
            const error = await rejection(clientOf(new FetchMock().answer({ status: 401, body: "" })).registerTenant(signedRegistration()));
            expect(error).toBeInstanceOf(RpcTransportError);
            expect(error).toMatchObject({ method: "lsp_register_tenant", message: "lsp_register_tenant: HTTP status 401", status: 401 });
        });

        it("surfaces a body that cannot be read as an RpcTransportError carrying the cause", async () => {
            const cause = new Error("stream reset");
            const mock = new FetchMock().answer({ status: 200, bodyError: cause });
            const error = await rejection(clientOf(mock).registerTenant(signedRegistration()));
            expect(error).toBeInstanceOf(RpcTransportError);
            expect(error).toMatchObject({
                method: "lsp_register_tenant",
                message: "lsp_register_tenant: the response body could not be read",
                status: 200,
            });
            expect((error as RpcTransportError).cause).toBe(cause);
        });

        it.each<[string, unknown, string, string]>([
            ["a null result", null, "response.result", "must be an object"],
            ["no tenant", { access_token: "tenant-access-token-cold" }, "response.result.tenant", "must be an object"],
            ["no access token", { tenant: COLD.tenant }, "response.result.access_token", "must be a non-empty string"],
            ["an empty access token", { ...COLD, access_token: "" }, "response.result.access_token", "must be a non-empty string"],
            [
                "a tenant without its id",
                { ...COLD, tenant: { ...COLD.tenant, tenant_id: undefined } },
                "response.result.tenant.tenant_id",
                "must be 32 bytes of lowercase hex without a 0x prefix",
            ],
        ])("refuses a result with %s as an RpcResponseError", async (_, result, path, reason) => {
            const error = await rejection(clientOf(answering(result)).registerTenant(signedRegistration()));
            expect(error).toBeInstanceOf(RpcResponseError);
            expect(error).toMatchObject({ method: "lsp_register_tenant", path, reason });
        });

        it.each<[string, unknown]>([
            ["undefined", undefined],
            ["null", null],
            ["an array", []],
            ["a string", "registration"],
        ])("refuses a registration that is %s before sending anything", async (_, registration) => {
            const mock = new FetchMock();
            const error = await rejection(clientOf(mock).registerTenant(registration as RegisterTenantParams));
            expect(error).toBeInstanceOf(TypeError);
            expect(error).toHaveProperty("message", "registration must be an object");
            expect(mock.requests).toHaveLength(0);
        });

        it.each<[string, Partial<Record<keyof RegisterTenantParams, unknown>>, Error]>([
            ["no root signer", { rootSignerPubkey: undefined }, new TypeError("registration.rootSignerPubkey must be a Uint8Array")],
            [
                "a root signer off the curve",
                { rootSignerPubkey: hexToBytes(`02${"ff".repeat(32)}`) },
                new TypeError("registration.rootSignerPubkey must be a compressed point on secp256k1"),
            ],
            ["no request id", { requestId: undefined }, new TypeError("registration.requestId must be a Uint8Array")],
            [
                "a request id of 31 bytes",
                { requestId: new Uint8Array(31) },
                new TypeError("registration.requestId must be 32 bytes, got 31"),
            ],
            [
                "no signing time",
                { signedAtMs: undefined },
                new RangeError("registration.signedAtMs must be a bigint between 0 and 18446744073709551615, got undefined"),
            ],
            [
                "a signing time past a u64",
                { signedAtMs: 2n ** 64n },
                new RangeError("registration.signedAtMs must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
            ],
            ["no signature", { signature: undefined }, new TypeError("registration.signature must be a Uint8Array")],
            [
                "a signature of 63 bytes",
                { signature: new Uint8Array(63) },
                new TypeError("registration.signature must be 64 bytes, got 63"),
            ],
        ])("refuses a registration with %s before sending anything", async (_, change, expected) => {
            const mock = new FetchMock();
            const registration = { ...signedRegistration(), ...change } as RegisterTenantParams;
            const error = await rejection(clientOf(mock).registerTenant(registration));
            expect(error).toBeInstanceOf(expected.constructor);
            expect(error).toHaveProperty("message", expected.message);
            expect(mock.requests).toHaveLength(0);
        });
    });
});
