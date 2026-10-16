import { COMPACT_ECDSA_SIGNATURE_LENGTH, COMPRESSED_POINT_LENGTH, HASH256_LENGTH, UINT64_MAX, isHexBytes } from "../common";
import type { WireField } from "../wire";
import {
    decodeBareHexBytes,
    decodeBoolean,
    decodeEnum,
    decodeHexBytes,
    decodeNonEmptyString,
    decodeOrNull,
    decodeUintHex,
    encodeBareHexBytes,
    encodeHexBytes,
    malformedWireField,
    readObject,
    requireHexBytes,
} from "../wire";
import { RPC_TENANT_RUNTIME_STATUSES } from "./rpc.constants";
import type {
    GetTenantRegistryNonceParams,
    GetTenantRegistryNonceParamsWire,
    GetTenantRegistryNonceResult,
    GetTenantRegistryNonceResultWire,
    LspTenantStatus,
    LspTenantStatusWire,
    RegisterTenantParams,
    RegisterTenantParamsWire,
    RegisterTenantResult,
    RegisterTenantResultWire,
} from "./rpc.types";

/**
 * Writes the params of `lsp_get_tenant_registry_nonce`.
 * @param params The root signer the nonce is issued to.
 * @returns The wire params.
 */
export function encodeGetTenantRegistryNonceParams(params: GetTenantRegistryNonceParams): GetTenantRegistryNonceParamsWire {
    return { root_signer_pubkey: encodeBareHexBytes("rootSignerPubkey", params.rootSignerPubkey, COMPRESSED_POINT_LENGTH) };
}

/**
 * Reads the result of `lsp_get_tenant_registry_nonce`.
 * @param field The result field.
 * @returns The LSP's node id, the root signer the nonce is bound to, and the nonce.
 */
export function decodeGetTenantRegistryNonceResult(field: WireField): GetTenantRegistryNonceResult {
    const at = readObject<GetTenantRegistryNonceResultWire>(field);
    return {
        lspNodeId: decodeBareHexBytes(at("lsp_node_id"), COMPRESSED_POINT_LENGTH),
        rootSignerPubkey: decodeBareHexBytes(at("root_signer_pubkey"), COMPRESSED_POINT_LENGTH),
        nonce: decodeHexBytes(at("nonce"), HASH256_LENGTH),
    };
}

/**
 * Writes the params of `lsp_register_tenant`, the signature as bare hex, as fiber's own agent writes it.
 * @param params The root signer, the nonce it was issued, and its signature over the registry payload.
 * @returns The wire params.
 */
export function encodeRegisterTenantParams(params: RegisterTenantParams): RegisterTenantParamsWire {
    return {
        root_signer_pubkey: encodeBareHexBytes("rootSignerPubkey", params.rootSignerPubkey, COMPRESSED_POINT_LENGTH),
        nonce: encodeHexBytes("nonce", params.nonce, HASH256_LENGTH),
        signature: encodeBareHexBytes("signature", params.signature, COMPACT_ECDSA_SIGNATURE_LENGTH),
    };
}

/**
 * Reads the result of `lsp_register_tenant`.
 * @param field The result field.
 * @returns The tenant as registered and its access token.
 */
export function decodeRegisterTenantResult(field: WireField): RegisterTenantResult {
    const at = readObject<RegisterTenantResultWire>(field);
    return { tenant: decodeLspTenantStatus(at("tenant")), accessToken: decodeNonEmptyString(at("access_token")) };
}

/**
 * Reads a tenant's status.
 * @param field Field to read.
 * @returns The status.
 */
function decodeLspTenantStatus(field: WireField): LspTenantStatus {
    const at = readObject<LspTenantStatusWire>(field);
    return {
        tenantId: decodeTenantId(at("tenant_id")),
        rootSignerPubkey: decodeOrNull(at("root_signer_pubkey"), (key) => decodeBareHexBytes(key, COMPRESSED_POINT_LENGTH)),
        invoicePubkey: decodeBareHexBytes(at("invoice_pubkey"), COMPRESSED_POINT_LENGTH),
        privateChannelId: decodeOrNull(at("private_channel_id"), (id) => requireHexBytes(id, HASH256_LENGTH)),
        createdAtMs: decodeUintHex(at("created_at"), UINT64_MAX),
        runtimeStatus: decodeEnum(at("runtime_status"), RPC_TENANT_RUNTIME_STATUSES),
        channelOnline: decodeBoolean(at("channel_online")),
    };
}

/**
 * Reads a tenant id: the bare hex of a 32-byte digest, kept as the string.
 * @param field Field to read.
 * @returns The id.
 */
function decodeTenantId(field: WireField): string {
    if (!isHexBytes(field.value, HASH256_LENGTH))
        malformedWireField(field, `must be ${HASH256_LENGTH} bytes of lowercase hex without a 0x prefix`);
    return field.value;
}
