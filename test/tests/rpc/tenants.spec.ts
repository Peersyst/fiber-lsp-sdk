import { hexToBytes } from "@noble/hashes/utils.js";
import type { RegisterTenantParams } from "../../../src/rpc";
import {
    FiberRpcClient,
    RPC_TENANT_RUNTIME_STATUSES,
    RpcError,
    RpcResponseError,
    decodeGetTenantRegistryNonceResult,
    decodeRegisterTenantResult,
    encodeGetTenantRegistryNonceParams,
    encodeRegisterTenantParams,
} from "../../../src/rpc";
import { FetchMock } from "../../mocks/rpc";
import { caseOf } from "../../utils/interop-vectors";
import { refusal } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import { RPC_RESULT_PATH as RESULT, answering, refusing, resultField as result, sent } from "../../utils/rpc-answers";
import {
    toGetTenantRegistryNonceParams,
    toGetTenantRegistryNonceResult,
    toRegisterTenantParams,
    toRegisterTenantResult,
    withoutNulls,
} from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { ABOVE_U64, U64_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const { lsp_get_tenant_registry_nonce: getNonce, lsp_register_tenant: register } = vectors.methods;

const URL = "http://fiber.example:8227";
const ROOT_SIGNER = `02${"ab".repeat(32)}`;
const LSP_NODE_ID = `03${"cd".repeat(32)}`;
const INVOICE_PUBKEY = `02${"ef".repeat(32)}`;
const NONCE = "9e".repeat(32);
const SIGNATURE = "1f".repeat(64);
const TENANT_ID = "4d".repeat(32);
const CHANNEL_ID = `0x${"11".repeat(32)}`;
const ACCESS_TOKEN = "En0KDjAxOTM0NzVhYjNjZGVmGAMiDgoMCIAIEgMYgQgSAxiCCBIkCAASIAEIfAEDZ";

const REGISTER: RegisterTenantParams = {
    rootSignerPubkey: hexToBytes(ROOT_SIGNER),
    nonce: hexToBytes(NONCE),
    signature: hexToBytes(SIGNATURE),
};

const ISSUED_NONCE = { lsp_node_id: LSP_NODE_ID, root_signer_pubkey: ROOT_SIGNER, nonce: `0x${NONCE}` };

const COLD_TENANT = {
    tenant_id: TENANT_ID,
    root_signer_pubkey: null,
    invoice_pubkey: INVOICE_PUBKEY,
    private_channel_id: null,
    created_at: "0x191dd9dec00",
    runtime_status: "cold",
    channel_online: false,
};

const ACTIVE_TENANT = {
    ...COLD_TENANT,
    root_signer_pubkey: ROOT_SIGNER,
    private_channel_id: CHANNEL_ID,
    runtime_status: "active",
    channel_online: true,
};

const REGISTERED = { tenant: COLD_TENANT, access_token: ACCESS_TOKEN };

describe("lsp_get_tenant_registry_nonce", () => {
    describe("encodeGetTenantRegistryNonceParams", () => {
        it("writes the root signer's key bare", () => {
            const wire = encodeGetTenantRegistryNonceParams({ rootSignerPubkey: hexToBytes(ROOT_SIGNER) });
            expect(wire).toEqual({ root_signer_pubkey: ROOT_SIGNER });
            expect(Object.keys(wire)).toEqual(["root_signer_pubkey"]);
        });

        it.each(getNonce.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeGetTenantRegistryNonceParams(toGetTenantRegistryNonceParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it.each<[string, unknown, Error]>([
            ["a key of 32 bytes", new Uint8Array(32), new TypeError("rootSignerPubkey must be 33 bytes, got 32")],
            ["a key of 34 bytes", new Uint8Array(34), new TypeError("rootSignerPubkey must be 33 bytes, got 34")],
            ["a key as hex", ROOT_SIGNER, new TypeError("rootSignerPubkey must be a Uint8Array")],
            ["a missing key", undefined, new TypeError("rootSignerPubkey must be a Uint8Array")],
        ])("refuses %s", (_, rootSignerPubkey, expected) => {
            expect(() => encodeGetTenantRegistryNonceParams({ rootSignerPubkey: rootSignerPubkey as Uint8Array })).toThrow(expected);
        });
    });

    describe("decodeGetTenantRegistryNonceResult", () => {
        it.each(getNonce.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeGetTenantRegistryNonceResult(result(entry.json))).toEqual(toGetTenantRegistryNonceResult(entry.values));
        });

        it("reads a literal answer field by field, the keys bare and the nonce prefixed", () => {
            expect(decodeGetTenantRegistryNonceResult(result(ISSUED_NONCE))).toEqual({
                lspNodeId: hexToBytes(LSP_NODE_ID),
                rootSignerPubkey: hexToBytes(ROOT_SIGNER),
                nonce: hexToBytes(NONCE),
            });
        });

        it("ignores the members it does not read", () => {
            expect(decodeGetTenantRegistryNonceResult(result({ ...ISSUED_NONCE, expires_at: "0x0" }))).toEqual(
                decodeGetTenantRegistryNonceResult(result(ISSUED_NONCE)),
            );
        });

        it.each([
            ["lsp_node_id", `0x${LSP_NODE_ID}`],
            ["lsp_node_id", LSP_NODE_ID.slice(2)],
            ["lsp_node_id", LSP_NODE_ID.toUpperCase()],
            ["lsp_node_id", undefined],
            ["lsp_node_id", null],
            ["root_signer_pubkey", `0x${ROOT_SIGNER}`],
            ["root_signer_pubkey", `${ROOT_SIGNER}00`],
            ["root_signer_pubkey", undefined],
            ["root_signer_pubkey", null],
            ["nonce", NONCE],
            ["nonce", `0x${"9e".repeat(31)}`],
            ["nonce", `0x${"9E".repeat(32)}`],
            ["nonce", undefined],
            ["nonce", null],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeGetTenantRegistryNonceResult(result(withField(ISSUED_NONCE, path, value)))).path).toBe(
                `${RESULT}.${path}`,
            );
        });

        it.each([null, [], NONCE])("refuses the result %p, which is not an object", (value) => {
            expect(refusal(() => decodeGetTenantRegistryNonceResult(result(value))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("lsp_register_tenant", () => {
    describe("encodeRegisterTenantParams", () => {
        it("writes the key and the signature bare and the nonce with its prefix", () => {
            const wire = encodeRegisterTenantParams(REGISTER);
            expect(wire).toEqual({ root_signer_pubkey: ROOT_SIGNER, nonce: `0x${NONCE}`, signature: SIGNATURE });
            expect(Object.keys(wire)).toEqual(["root_signer_pubkey", "nonce", "signature"]);
            expect(wire.signature).toHaveLength(128);
        });

        it.each(register.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeRegisterTenantParams(toRegisterTenantParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["a key of 32 bytes", { rootSignerPubkey: new Uint8Array(32) }, new TypeError("rootSignerPubkey must be 33 bytes, got 32")],
            ["a key as hex", { rootSignerPubkey: ROOT_SIGNER }, new TypeError("rootSignerPubkey must be a Uint8Array")],
            ["a missing key", { rootSignerPubkey: undefined }, new TypeError("rootSignerPubkey must be a Uint8Array")],
            ["a nonce of 31 bytes", { nonce: new Uint8Array(31) }, new TypeError("nonce must be 32 bytes, got 31")],
            ["a nonce of 33 bytes", { nonce: new Uint8Array(33) }, new TypeError("nonce must be 32 bytes, got 33")],
            ["a nonce as hex", { nonce: `0x${NONCE}` }, new TypeError("nonce must be a Uint8Array")],
            ["a missing nonce", { nonce: undefined }, new TypeError("nonce must be a Uint8Array")],
            ["a signature of 63 bytes", { signature: new Uint8Array(63) }, new TypeError("signature must be 64 bytes, got 63")],
            ["a recoverable signature of 65 bytes", { signature: new Uint8Array(65) }, new TypeError("signature must be 64 bytes, got 65")],
            ["a signature as hex", { signature: SIGNATURE }, new TypeError("signature must be a Uint8Array")],
            ["a missing signature", { signature: undefined }, new TypeError("signature must be a Uint8Array")],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeRegisterTenantParams({ ...REGISTER, ...change } as RegisterTenantParams)).toThrow(expected);
        });
    });

    describe("decodeRegisterTenantResult", () => {
        it.each(register.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeRegisterTenantResult(result(entry.json))).toEqual(toRegisterTenantResult(entry.values));
        });

        it("reads a cold tenant without a channel field by field", () => {
            expect(decodeRegisterTenantResult(result(REGISTERED))).toEqual({
                tenant: {
                    tenantId: TENANT_ID,
                    rootSignerPubkey: null,
                    invoicePubkey: hexToBytes(INVOICE_PUBKEY),
                    privateChannelId: null,
                    createdAtMs: 1726000000000n,
                    runtimeStatus: "cold",
                    channelOnline: false,
                },
                accessToken: ACCESS_TOKEN,
            });
        });

        it("reads an active tenant with its root signer and its channel, the id as the wire string", () => {
            expect(decodeRegisterTenantResult(result({ ...REGISTERED, tenant: ACTIVE_TENANT })).tenant).toEqual({
                tenantId: TENANT_ID,
                rootSignerPubkey: hexToBytes(ROOT_SIGNER),
                invoicePubkey: hexToBytes(INVOICE_PUBKEY),
                privateChannelId: CHANNEL_ID,
                createdAtMs: 1726000000000n,
                runtimeStatus: "active",
                channelOnline: true,
            });
        });

        it.each(RPC_TENANT_RUNTIME_STATUSES)("reads the runtime status %s", (status) => {
            expect(
                decodeRegisterTenantResult(result({ ...REGISTERED, tenant: { ...COLD_TENANT, runtime_status: status } })).tenant
                    .runtimeStatus,
            ).toBe(status);
        });

        it("reads the largest creation time", () => {
            expect(
                decodeRegisterTenantResult(result({ ...REGISTERED, tenant: { ...COLD_TENANT, created_at: U64_MAX_HEX } })).tenant
                    .createdAtMs,
            ).toBe(2n ** 64n - 1n);
        });

        it("ignores the members it does not read", () => {
            const loose = { ...REGISTERED, tenant: { ...COLD_TENANT, watchtower_node_id: 5 }, expires_at: null };
            expect(decodeRegisterTenantResult(result(loose))).toEqual(decodeRegisterTenantResult(result(REGISTERED)));
        });

        it.each([
            ["tenant", undefined],
            ["tenant", null],
            ["tenant", TENANT_ID],
            ["tenant.tenant_id", `0x${TENANT_ID}`],
            ["tenant.tenant_id", "4d".repeat(31)],
            ["tenant.tenant_id", "4d".repeat(33)],
            ["tenant.tenant_id", TENANT_ID.toUpperCase()],
            ["tenant.tenant_id", ""],
            ["tenant.tenant_id", undefined],
            ["tenant.tenant_id", null],
            ["tenant.tenant_id", 1],
            ["tenant.root_signer_pubkey", `0x${ROOT_SIGNER}`],
            ["tenant.root_signer_pubkey", ROOT_SIGNER.slice(2)],
            ["tenant.root_signer_pubkey", ROOT_SIGNER.toUpperCase()],
            ["tenant.root_signer_pubkey", undefined],
            ["tenant.invoice_pubkey", `0x${INVOICE_PUBKEY}`],
            ["tenant.invoice_pubkey", `${INVOICE_PUBKEY}00`],
            ["tenant.invoice_pubkey", undefined],
            ["tenant.invoice_pubkey", null],
            ["tenant.private_channel_id", CHANNEL_ID.slice(2)],
            ["tenant.private_channel_id", `0x${"11".repeat(31)}`],
            ["tenant.private_channel_id", `0x${"AA".repeat(32)}`],
            ["tenant.private_channel_id", undefined],
            ["tenant.created_at", "1726000000000"],
            ["tenant.created_at", "0x0191dd9dec00"],
            ["tenant.created_at", ABOVE_U64],
            ["tenant.created_at", 1726000000000],
            ["tenant.created_at", undefined],
            ["tenant.created_at", null],
            ["tenant.runtime_status", "Cold"],
            ["tenant.runtime_status", "active "],
            ["tenant.runtime_status", "warm"],
            ["tenant.runtime_status", undefined],
            ["tenant.runtime_status", null],
            ["tenant.runtime_status", 1],
            ["tenant.channel_online", "true"],
            ["tenant.channel_online", 1],
            ["tenant.channel_online", undefined],
            ["tenant.channel_online", null],
            ["access_token", ""],
            ["access_token", undefined],
            ["access_token", null],
            ["access_token", 1],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeRegisterTenantResult(result(withField(REGISTERED, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it("lists the runtime statuses fiber has in the refusal of another", () => {
            expect(
                refusal(() => decodeRegisterTenantResult(result({ ...REGISTERED, tenant: { ...COLD_TENANT, runtime_status: "warm" } })))
                    .message,
            ).toBe(`${RESULT}.tenant.runtime_status must be one of cold, active`);
        });

        it("says what a tenant id has to be", () => {
            expect(
                refusal(() => decodeRegisterTenantResult(result({ ...REGISTERED, tenant: { ...COLD_TENANT, tenant_id: "ops-1" } })))
                    .message,
            ).toBe(`${RESULT}.tenant.tenant_id must be 32 bytes of lowercase hex without a 0x prefix`);
        });

        it.each([null, [], ACCESS_TOKEN])("refuses the result %p, which is not an object", (value) => {
            expect(refusal(() => decodeRegisterTenantResult(result(value))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("FiberRpcClient registration methods", () => {
    function clientOf(mock: FetchMock): FiberRpcClient {
        return new FiberRpcClient({ url: URL, token: "operator-token", fetch: mock.fetch });
    }

    it("asks for a nonce through call, under the operator's token", async () => {
        const entry = caseOf(getNonce.results, "nonce");
        const mock = answering(entry.json);
        const params = encodeGetTenantRegistryNonceParams({ rootSignerPubkey: hexToBytes(ROOT_SIGNER) });
        await expect(clientOf(mock).call("lsp_get_tenant_registry_nonce", params, decodeGetTenantRegistryNonceResult)).resolves.toEqual(
            toGetTenantRegistryNonceResult(entry.values),
        );
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "lsp_get_tenant_registry_nonce",
            params: [{ root_signer_pubkey: ROOT_SIGNER }],
        });
        expect(mock.last.init.headers.authorization).toBe("Bearer operator-token");
    });

    it("registers a tenant through call, sending the exact body with the signature bare", async () => {
        const mock = answering(REGISTERED);
        await expect(
            clientOf(mock).call("lsp_register_tenant", encodeRegisterTenantParams(REGISTER), decodeRegisterTenantResult),
        ).resolves.toEqual(decodeRegisterTenantResult(result(REGISTERED)));
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "lsp_register_tenant",
            params: [{ root_signer_pubkey: ROOT_SIGNER, nonce: `0x${NONCE}`, signature: SIGNATURE }],
        });
    });

    it("passes the node's refusal through, its message verbatim", async () => {
        const mock = refusing(-32000, "nonce expired");
        const error = await rejection(
            clientOf(mock).call("lsp_register_tenant", encodeRegisterTenantParams(REGISTER), decodeRegisterTenantResult),
        );
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "lsp_register_tenant", code: -32000, message: "nonce expired" });
    });

    it("names the nested field of an answer it cannot read", async () => {
        const mock = answering({ ...REGISTERED, tenant: { ...COLD_TENANT, runtime_status: "warm" } });
        const error = await rejection(
            clientOf(mock).call("lsp_register_tenant", encodeRegisterTenantParams(REGISTER), decodeRegisterTenantResult),
        );
        expect(error).toBeInstanceOf(RpcResponseError);
        expect(error).toMatchObject({ method: "lsp_register_tenant", path: "response.result.tenant.runtime_status" });
    });
});
