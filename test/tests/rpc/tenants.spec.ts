import { hexToBytes } from "@noble/hashes/utils.js";
import type { RegisterTenantParams } from "../../../src/rpc";
import { RPC_TENANT_RUNTIME_STATUSES, decodeRegisterTenantResult, encodeRegisterTenantParams } from "../../../src/rpc";
import { refusal } from "../../utils/refusal";
import { RPC_RESULT_PATH as RESULT, resultField as result } from "../../utils/rpc-answers";
import { toRegisterTenantParams, toRegisterTenantResult, withoutNulls } from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { ABOVE_U64, U64_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const { lsp_register_tenant: register } = vectors.methods;

const ROOT_SIGNER = `02${"ab".repeat(32)}`;
const INVOICE_PUBKEY = `02${"ef".repeat(32)}`;
const REQUEST_ID = "9e".repeat(32);
const SIGNATURE = "1f".repeat(64);
const TENANT_ID = "4d".repeat(32);
const CKB_CHANNEL_ID = `0x${"11".repeat(32)}`;
const UDT_CHANNEL_ID = `0x${"12".repeat(32)}`;
const ACCESS_TOKEN = "En0KDjAxOTM0NzVhYjNjZGVmGAMiDgoMCIAIEgMYgQgSAxiCCBIkCAASIAEIfAEDZ";

const REGISTER: RegisterTenantParams = {
    rootSignerPubkey: hexToBytes(ROOT_SIGNER),
    requestId: hexToBytes(REQUEST_ID),
    signedAtMs: 1762041600000n,
    signature: hexToBytes(SIGNATURE),
};

const COLD_TENANT = {
    tenant_id: TENANT_ID,
    root_signer_pubkey: null,
    invoice_pubkey: INVOICE_PUBKEY,
    channels: [],
    created_at: "0x191dd9dec00",
    runtime_status: "cold",
};

const CKB_CHANNEL = { channel_id: CKB_CHANNEL_ID, funding_udt_type_script: null, online: true };

const UDT_CHANNEL = {
    channel_id: UDT_CHANNEL_ID,
    funding_udt_type_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"e3".repeat(32)}` },
    online: false,
};

const ACTIVE_TENANT = {
    tenant_id: TENANT_ID,
    root_signer_pubkey: ROOT_SIGNER,
    invoice_pubkey: INVOICE_PUBKEY,
    channels: [CKB_CHANNEL, UDT_CHANNEL],
    created_at: "0x191dd9dec00",
    runtime_status: "active",
};

const REGISTERED = { tenant: COLD_TENANT, access_token: ACCESS_TOKEN };

const REGISTERED_ACTIVE = { tenant: ACTIVE_TENANT, access_token: ACCESS_TOKEN };

describe("lsp_register_tenant", () => {
    describe("encodeRegisterTenantParams", () => {
        it("writes the key and the signature bare, the request id with its prefix and the signing time in hex, in fiber's order", () => {
            const wire = encodeRegisterTenantParams(REGISTER);
            expect(wire).toEqual({
                root_signer_pubkey: ROOT_SIGNER,
                request_id: `0x${REQUEST_ID}`,
                signed_at: "0x19a41dd1800",
                signature: SIGNATURE,
            });
            expect(Object.keys(wire)).toEqual(["root_signer_pubkey", "request_id", "signed_at", "signature"]);
            expect(wire.signature).toHaveLength(128);
        });

        it("writes the bounds of the signing time", () => {
            expect(encodeRegisterTenantParams({ ...REGISTER, signedAtMs: 0n }).signed_at).toBe("0x0");
            expect(encodeRegisterTenantParams({ ...REGISTER, signedAtMs: 2n ** 64n - 1n }).signed_at).toBe(U64_MAX_HEX);
        });

        it.each(register.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeRegisterTenantParams(toRegisterTenantParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["a key of 32 bytes", { rootSignerPubkey: new Uint8Array(32) }, new TypeError("rootSignerPubkey must be 33 bytes, got 32")],
            ["a key as hex", { rootSignerPubkey: ROOT_SIGNER }, new TypeError("rootSignerPubkey must be a Uint8Array")],
            ["a missing key", { rootSignerPubkey: undefined }, new TypeError("rootSignerPubkey must be a Uint8Array")],
            ["a null key", { rootSignerPubkey: null }, new TypeError("rootSignerPubkey must be a Uint8Array")],
            ["a request id of 31 bytes", { requestId: new Uint8Array(31) }, new TypeError("requestId must be 32 bytes, got 31")],
            ["a request id of 33 bytes", { requestId: new Uint8Array(33) }, new TypeError("requestId must be 32 bytes, got 33")],
            ["a request id as hex", { requestId: `0x${REQUEST_ID}` }, new TypeError("requestId must be a Uint8Array")],
            ["a missing request id", { requestId: undefined }, new TypeError("requestId must be a Uint8Array")],
            ["a null request id", { requestId: null }, new TypeError("requestId must be a Uint8Array")],
            [
                "a signing time past a u64",
                { signedAtMs: 2n ** 64n },
                new RangeError("signedAtMs must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
            ],
            [
                "a negative signing time",
                { signedAtMs: -1n },
                new RangeError("signedAtMs must be a bigint between 0 and 18446744073709551615, got -1"),
            ],
            [
                "a signing time as a number",
                { signedAtMs: 1762041600000 },
                new RangeError("signedAtMs must be a bigint between 0 and 18446744073709551615, got 1762041600000"),
            ],
            [
                "a signing time as a string",
                { signedAtMs: "1762041600000" },
                new RangeError("signedAtMs must be a bigint between 0 and 18446744073709551615, got 1762041600000"),
            ],
            [
                "a missing signing time",
                { signedAtMs: undefined },
                new RangeError("signedAtMs must be a bigint between 0 and 18446744073709551615, got undefined"),
            ],
            [
                "a null signing time",
                { signedAtMs: null },
                new RangeError("signedAtMs must be a bigint between 0 and 18446744073709551615, got null"),
            ],
            ["a signature of 63 bytes", { signature: new Uint8Array(63) }, new TypeError("signature must be 64 bytes, got 63")],
            ["a recoverable signature of 65 bytes", { signature: new Uint8Array(65) }, new TypeError("signature must be 64 bytes, got 65")],
            ["a signature as hex", { signature: SIGNATURE }, new TypeError("signature must be a Uint8Array")],
            ["a missing signature", { signature: undefined }, new TypeError("signature must be a Uint8Array")],
            ["a null signature", { signature: null }, new TypeError("signature must be a Uint8Array")],
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
                    channels: [],
                    createdAtMs: 1726000000000n,
                    runtimeStatus: "cold",
                },
                accessToken: ACCESS_TOKEN,
            });
        });

        it("reads an active tenant with its root signer and its channels in the node's order, the ids as the wire string", () => {
            expect(decodeRegisterTenantResult(result(REGISTERED_ACTIVE)).tenant).toEqual({
                tenantId: TENANT_ID,
                rootSignerPubkey: hexToBytes(ROOT_SIGNER),
                invoicePubkey: hexToBytes(INVOICE_PUBKEY),
                channels: [
                    { channelId: CKB_CHANNEL_ID, fundingUdtTypeScript: null, online: true },
                    {
                        channelId: UDT_CHANNEL_ID,
                        fundingUdtTypeScript: {
                            codeHash: hexToBytes("9b".repeat(32)),
                            hashType: "type",
                            args: hexToBytes("e3".repeat(32)),
                        },
                        online: false,
                    },
                ],
                createdAtMs: 1726000000000n,
                runtimeStatus: "active",
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

        it("ignores the members it does not read, in the result, the tenant and a channel", () => {
            const loose = {
                ...REGISTERED_ACTIVE,
                tenant: { ...ACTIVE_TENANT, watchtower_node_id: 5, channels: [{ ...CKB_CHANNEL, capacity: "0x0" }, UDT_CHANNEL] },
                expires_at: null,
            };
            expect(decodeRegisterTenantResult(result(loose))).toEqual(decodeRegisterTenantResult(result(REGISTERED_ACTIVE)));
        });

        it("refuses a tenant written in the single-channel shape, which has no channels", () => {
            const single = { ...COLD_TENANT, channels: undefined, private_channel_id: CKB_CHANNEL_ID, channel_online: true };
            expect(refusal(() => decodeRegisterTenantResult(result({ ...REGISTERED, tenant: single }))).path).toBe(
                `${RESULT}.tenant.channels`,
            );
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
            ["tenant.channels", undefined],
            ["tenant.channels", null],
            ["tenant.channels", CKB_CHANNEL],
            ["tenant.channels", CKB_CHANNEL_ID],
            ["tenant.channels[0]", null],
            ["tenant.channels[1]", UDT_CHANNEL_ID],
            ["tenant.channels[0].channel_id", CKB_CHANNEL_ID.slice(2)],
            ["tenant.channels[0].channel_id", `0x${"11".repeat(31)}`],
            ["tenant.channels[0].channel_id", `0x${"AA".repeat(32)}`],
            ["tenant.channels[0].channel_id", undefined],
            ["tenant.channels[1].channel_id", null],
            ["tenant.channels[0].funding_udt_type_script", undefined],
            ["tenant.channels[0].funding_udt_type_script", "xudt"],
            ["tenant.channels[1].funding_udt_type_script.code_hash", `0x${"9b".repeat(31)}`],
            ["tenant.channels[1].funding_udt_type_script.hash_type", "data3"],
            ["tenant.channels[1].funding_udt_type_script.args", "e3".repeat(32)],
            ["tenant.channels[1].funding_udt_type_script.args", undefined],
            ["tenant.channels[0].online", "true"],
            ["tenant.channels[0].online", 1],
            ["tenant.channels[0].online", undefined],
            ["tenant.channels[1].online", null],
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
            ["access_token", ""],
            ["access_token", undefined],
            ["access_token", null],
            ["access_token", 1],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeRegisterTenantResult(result(withField(REGISTERED_ACTIVE, path, value)))).path).toBe(
                `${RESULT}.${path}`,
            );
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
